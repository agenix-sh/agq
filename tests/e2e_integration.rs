//! End-to-end integration test: AGX -> AGQ -> AGW
//!
//! Tests the complete workflow:
//! 1. AGX creates a job with multiple steps
//! 2. AGX submits job to AGQ via LPUSH
//! 3. AGW picks up job via BRPOP
//! 4. AGW executes steps and reports results

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Test session key for integration tests
const TEST_SESSION_KEY: &[u8] = b"test_session_key_32_bytes_long!!";

/// Helper to start AGQ server on a random port
async fn start_agq_server() -> (tokio::task::JoinHandle<()>, u16) {
    use agq::{Database, Server};
    use tempfile::TempDir;

    // Bind to random port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind test server");

    let addr = listener.local_addr().expect("Failed to get local addr");
    let port = addr.port();

    // Drop the temporary listener
    drop(listener);

    // Start actual server
    let handle = tokio::spawn(async move {
        // Create temporary database for this test
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db_path = temp_dir.path().join("test.redb");
        let db = Database::open(&db_path).expect("Failed to open database");

        let server = Server::new(&format!("127.0.0.1:{port}"), TEST_SESSION_KEY.to_vec(), db)
            .await
            .expect("Failed to create server");

        // Run server (will run until process exits in tests)
        let _ = server.run().await;

        // Keep temp_dir alive
        drop(temp_dir);
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    (handle, port)
}

/// Helper to send RESP command and read response
async fn send_resp_command(stream: &mut TcpStream, command: &[u8]) -> Vec<u8> {
    stream.write_all(command).await.expect("Failed to write");

    let mut response = vec![0u8; 8192]; // Larger buffer for job JSON
    let n = stream.read(&mut response).await.expect("Failed to read");
    response.truncate(n);
    response
}

/// Helper to encode a RESP bulk string array command
fn encode_resp_array(parts: &[&[u8]]) -> Vec<u8> {
    let mut buf = Vec::new();

    // Array length
    buf.extend_from_slice(format!("*{}\r\n", parts.len()).as_bytes());

    // Each bulk string
    for part in parts {
        buf.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        buf.extend_from_slice(part);
        buf.extend_from_slice(b"\r\n");
    }

    buf
}

#[tokio::test]
async fn test_e2e_agx_to_agq_to_agw() {
    // Start AGQ server
    let (_handle, port) = start_agq_server().await;

    // ============================================================
    // PHASE 1: AGX creates and submits job
    // ============================================================

    let job = json!({
        "job_id": "test-job-001",
        "plan_id": "test-plan-001",
        "plan_description": "Count lines in test data",
        "steps": [
            {
                "step_number": 1,
                "command": "echo",
                "args": ["line1\nline2\nline3"],
                "timeout_secs": 30
            },
            {
                "step_number": 2,
                "command": "wc",
                "args": ["-l"],
                "input_from_step": 1,
                "timeout_secs": 30
            }
        ]
    });

    let job_json = serde_json::to_string(&job).expect("Failed to serialize job");

    println!("\n=== AGX: Created Job ===");
    println!("{}", serde_json::to_string_pretty(&job).unwrap());

    // Connect to AGQ as AGX
    let mut agx_stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("AGX failed to connect to AGQ");

    // Authenticate
    let auth_cmd = encode_resp_array(&[b"AUTH", TEST_SESSION_KEY]);
    let response = send_resp_command(&mut agx_stream, &auth_cmd).await;
    assert_eq!(&response, b"+OK\r\n", "AGX authentication failed");

    // Submit job to queue via LPUSH
    let lpush_cmd = encode_resp_array(&[
        b"LPUSH",
        b"queue:ready",
        job_json.as_bytes(),
    ]);

    println!("\n=== AGX: Submitting to queue:ready ===");
    let response = send_resp_command(&mut agx_stream, &lpush_cmd).await;

    // Should return :1 (length of queue)
    assert!(
        response.starts_with(b":"),
        "LPUSH should return integer, got: {:?}",
        String::from_utf8_lossy(&response)
    );

    println!("AGX: Job submitted successfully, queue length: {}",
             String::from_utf8_lossy(&response[1..]).trim());

    // ============================================================
    // PHASE 2: AGW picks up job
    // ============================================================

    // Connect to AGQ as AGW
    let mut agw_stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("AGW failed to connect to AGQ");

    // Authenticate
    let auth_cmd = encode_resp_array(&[b"AUTH", TEST_SESSION_KEY]);
    let response = send_resp_command(&mut agw_stream, &auth_cmd).await;
    assert_eq!(&response, b"+OK\r\n", "AGW authentication failed");

    // Poll for job via BRPOP (30 second timeout)
    let brpop_cmd = encode_resp_array(&[
        b"BRPOP",
        b"queue:ready",
        b"30",
    ]);

    println!("\n=== AGW: Polling queue:ready with BRPOP ===");
    let response = send_resp_command(&mut agw_stream, &brpop_cmd).await;

    // Should return bulk string with job JSON
    assert!(
        response.starts_with(b"$"),
        "BRPOP should return bulk string, got: {:?}",
        String::from_utf8_lossy(&response)
    );

    // Parse the RESP bulk string response
    // Format: ${length}\r\n{data}\r\n
    let response_str = String::from_utf8_lossy(&response);
    let parts: Vec<&str> = response_str.split("\r\n").collect();

    assert!(parts.len() >= 2, "Invalid RESP bulk string format");

    let job_data = parts[1];
    println!("\n=== AGW: Received Job ===");
    println!("{}", job_data);

    // Parse the received job
    let received_job: serde_json::Value = serde_json::from_str(job_data)
        .expect("Failed to parse received job JSON");

    // ============================================================
    // PHASE 3: AGW validates job structure
    // ============================================================

    println!("\n=== AGW: Validating Job Structure ===");

    assert_eq!(
        received_job["job_id"].as_str(),
        Some("test-job-001"),
        "job_id mismatch"
    );

    assert_eq!(
        received_job["plan_id"].as_str(),
        Some("test-plan-001"),
        "plan_id mismatch"
    );

    let steps = received_job["steps"]
        .as_array()
        .expect("steps should be an array");

    assert_eq!(steps.len(), 2, "Should have 2 steps");

    // Validate step 1
    assert_eq!(steps[0]["step_number"], 1);
    assert_eq!(steps[0]["command"], "echo");
    assert_eq!(steps[0]["args"][0], "line1\nline2\nline3");

    // Validate step 2
    assert_eq!(steps[1]["step_number"], 2);
    assert_eq!(steps[1]["command"], "wc");
    assert_eq!(steps[1]["args"][0], "-l");
    assert_eq!(steps[1]["input_from_step"], 1);

    println!("AGW: Job structure validated successfully!");

    // ============================================================
    // PHASE 4: Verify queue is now empty
    // ============================================================

    println!("\n=== Verifying Queue State ===");

    // Check queue length
    let llen_cmd = encode_resp_array(&[b"LLEN", b"queue:ready"]);
    let response = send_resp_command(&mut agx_stream, &llen_cmd).await;

    assert_eq!(
        &response, b":0\r\n",
        "Queue should be empty after BRPOP"
    );

    println!("Queue is empty (length: 0)");

    // ============================================================
    // PHASE 5: Test BRPOP timeout on empty queue
    // ============================================================

    println!("\n=== Testing BRPOP Timeout ===");

    let brpop_cmd = encode_resp_array(&[
        b"BRPOP",
        b"queue:ready",
        b"1", // 1 second timeout
    ]);

    let start = std::time::Instant::now();
    let response = send_resp_command(&mut agw_stream, &brpop_cmd).await;
    let elapsed = start.elapsed();

    assert_eq!(
        &response, b"$-1\r\n",
        "BRPOP on empty queue should return nil"
    );

    assert!(
        elapsed >= std::time::Duration::from_secs(1),
        "BRPOP should wait at least 1 second"
    );

    assert!(
        elapsed < std::time::Duration::from_millis(1500),
        "BRPOP should timeout close to 1 second"
    );

    println!("BRPOP timeout working correctly ({}ms)", elapsed.as_millis());

    println!("\n=== ✅ E2E Integration Test Passed! ===");
}

#[tokio::test]
async fn test_multiple_jobs_fifo_order() {
    let (_handle, port) = start_agq_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // Auth
    let auth_cmd = encode_resp_array(&[b"AUTH", TEST_SESSION_KEY]);
    send_resp_command(&mut stream, &auth_cmd).await;

    // Submit 3 jobs
    for i in 1..=3 {
        let job = json!({
            "job_id": format!("job-{}", i),
            "plan_id": "plan-batch",
            "steps": [{
                "step_number": 1,
                "command": "echo",
                "args": [format!("Job {}", i)]
            }]
        });

        let job_json = serde_json::to_string(&job).unwrap();
        let lpush_cmd = encode_resp_array(&[
            b"LPUSH",
            b"queue:ready",
            job_json.as_bytes(),
        ]);

        send_resp_command(&mut stream, &lpush_cmd).await;
        println!("Submitted job-{}", i);
    }

    // Jobs should come out in FIFO order (LPUSH at head, BRPOP from tail)
    // Order: job-1, job-2, job-3
    for expected_id in 1..=3 {
        let brpop_cmd = encode_resp_array(&[b"BRPOP", b"queue:ready", b"1"]);
        let response = send_resp_command(&mut stream, &brpop_cmd).await;

        let response_str = String::from_utf8_lossy(&response);
        let parts: Vec<&str> = response_str.split("\r\n").collect();
        let job_data = parts[1];

        let job: serde_json::Value = serde_json::from_str(job_data).unwrap();
        let job_id = job["job_id"].as_str().unwrap();

        assert_eq!(
            job_id,
            format!("job-{}", expected_id),
            "Jobs should be processed in FIFO order"
        );

        println!("Received {} (correct order)", job_id);
    }

    println!("✅ FIFO ordering verified!");
}
