//! Integration tests for RESP protocol commands
//!
//! Tests the minimal RESP server implementation with AUTH and PING commands.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Test session key for integration tests
const TEST_SESSION_KEY: &[u8] = b"test_session_key_32_bytes_long!!";

/// Helper to start the AGQ server on a random port for testing
async fn start_test_server() -> (tokio::task::JoinHandle<()>, u16) {
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

    let mut response = vec![0u8; 1024];
    let n = stream.read(&mut response).await.expect("Failed to read");
    response.truncate(n);
    response
}

#[tokio::test]
async fn test_auth_command_success() {
    // Start server
    let (_handle, port) = start_test_server().await;

    // Connect
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // Send AUTH command with session key
    // RESP format: *2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    let response = send_resp_command(&mut stream, auth_cmd).await;

    // Expect +OK\r\n
    assert_eq!(&response, b"+OK\r\n", "AUTH should return +OK");
}

#[tokio::test]
async fn test_auth_command_missing_key() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH without key: *1\r\n$4\r\nAUTH\r\n
    let auth_cmd = b"*1\r\n$4\r\nAUTH\r\n";
    let response = send_resp_command(&mut stream, auth_cmd).await;

    // Expect error
    assert!(
        response.starts_with(b"-ERR"),
        "AUTH without key should return error"
    );
}

#[tokio::test]
async fn test_auth_command_empty_key() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH with empty key: *2\r\n$4\r\nAUTH\r\n$0\r\n\r\n
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$0\r\n\r\n";
    let response = send_resp_command(&mut stream, auth_cmd).await;

    // Expect error
    assert!(
        response.starts_with(b"-ERR"),
        "AUTH with empty key should return error"
    );
}

#[tokio::test]
async fn test_ping_command_after_auth() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // First AUTH
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    let auth_response = send_resp_command(&mut stream, auth_cmd).await;
    assert_eq!(&auth_response, b"+OK\r\n");

    // Then PING: *1\r\n$4\r\nPING\r\n
    let ping_cmd = b"*1\r\n$4\r\nPING\r\n";
    let ping_response = send_resp_command(&mut stream, ping_cmd).await;

    // Expect +PONG\r\n
    assert_eq!(&ping_response, b"+PONG\r\n", "PING should return +PONG");
}

#[tokio::test]
async fn test_ping_without_auth() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // Send PING without AUTH
    let ping_cmd = b"*1\r\n$4\r\nPING\r\n";
    let response = send_resp_command(&mut stream, ping_cmd).await;

    // Expect authentication error
    assert!(
        response.starts_with(b"-ERR"),
        "PING without AUTH should return error"
    );
    assert!(
        String::from_utf8_lossy(&response).contains("NOAUTH"),
        "Error should indicate authentication required"
    );
}

#[tokio::test]
async fn test_ping_with_message() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // PING with message: *2\r\n$4\r\nPING\r\n$5\r\nhello\r\n
    let ping_cmd = b"*2\r\n$4\r\nPING\r\n$5\r\nhello\r\n";
    let response = send_resp_command(&mut stream, ping_cmd).await;

    // Expect $5\r\nhello\r\n (bulk string echo)
    assert_eq!(
        &response, b"$5\r\nhello\r\n",
        "PING with message should echo message"
    );
}

#[tokio::test]
async fn test_invalid_command() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // Send unknown command: *1\r\n$7\r\nUNKNOWN\r\n
    let invalid_cmd = b"*1\r\n$7\r\nUNKNOWN\r\n";
    let response = send_resp_command(&mut stream, invalid_cmd).await;

    // Expect error
    assert!(
        response.starts_with(b"-ERR"),
        "Unknown command should return error"
    );
}

#[tokio::test]
async fn test_malformed_resp_command() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // Send malformed RESP (missing \r\n)
    let malformed_cmd = b"*1\r\n$4\r\nPING";
    stream
        .write_all(malformed_cmd)
        .await
        .expect("Failed to write");

    // Should either timeout or return error
    let mut response = vec![0u8; 1024];
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(1),
        stream.read(&mut response),
    )
    .await;

    // Either times out (no response) or gets error
    if let Ok(Ok(n)) = result {
        response.truncate(n);
        assert!(
            response.starts_with(b"-ERR"),
            "Malformed command should return error"
        );
    }
}

#[tokio::test]
async fn test_oversized_command() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // Send command with oversized argument (> 1MB)
    let size = 2 * 1024 * 1024; // 2MB
    let oversized_cmd = format!("*2\r\n$4\r\nAUTH\r\n${size}\r\n");
    stream
        .write_all(oversized_cmd.as_bytes())
        .await
        .expect("Failed to write");

    let mut response = vec![0u8; 1024];
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        stream.read(&mut response),
    )
    .await;

    // Should get error or connection close
    if let Ok(Ok(n)) = result {
        if n > 0 {
            response.truncate(n);
            assert!(
                response.starts_with(b"-ERR"),
                "Oversized command should return error"
            );
        }
    }
}

#[tokio::test]
async fn test_concurrent_connections() {
    let (_handle, port) = start_test_server().await;

    // Spawn 10 concurrent clients
    let mut handles = vec![];

    for _i in 0..10 {
        let handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .expect("Failed to connect");

            // AUTH
            let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
            stream.write_all(auth_cmd).await.expect("Failed to write");

            let mut response = vec![0u8; 1024];
            let n = stream.read(&mut response).await.expect("Failed to read");
            response.truncate(n);
            assert_eq!(&response, b"+OK\r\n");

            // PING
            let ping_cmd = b"*1\r\n$4\r\nPING\r\n";
            stream.write_all(ping_cmd).await.expect("Failed to write");

            let mut response = vec![0u8; 1024];
            let n = stream.read(&mut response).await.expect("Failed to read");
            response.truncate(n);
            assert_eq!(&response, b"+PONG\r\n");
        });

        handles.push(handle);
    }

    // Wait for all clients
    for handle in handles {
        handle.await.expect("Client task failed");
    }
}

#[tokio::test]
async fn test_set_and_get_commands() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // SET mykey myvalue: *3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n
    let set_cmd = b"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n";
    let response = send_resp_command(&mut stream, set_cmd).await;
    assert_eq!(&response, b"+OK\r\n", "SET should return +OK");

    // GET mykey: *2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n
    let get_cmd = b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
    let response = send_resp_command(&mut stream, get_cmd).await;
    assert_eq!(
        &response, b"$7\r\nmyvalue\r\n",
        "GET should return stored value"
    );
}

#[tokio::test]
async fn test_get_nonexistent_key() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // GET nonexistent: *2\r\n$3\r\nGET\r\n$11\r\nnonexistent\r\n
    let get_cmd = b"*2\r\n$3\r\nGET\r\n$11\r\nnonexistent\r\n";
    let response = send_resp_command(&mut stream, get_cmd).await;
    assert_eq!(&response, b"$-1\r\n", "GET nonexistent should return nil");
}

#[tokio::test]
async fn test_del_command() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // SET testkey testvalue
    let set_cmd = b"*3\r\n$3\r\nSET\r\n$7\r\ntestkey\r\n$9\r\ntestvalue\r\n";
    send_resp_command(&mut stream, set_cmd).await;

    // DEL testkey: *2\r\n$3\r\nDEL\r\n$7\r\ntestkey\r\n
    let del_cmd = b"*2\r\n$3\r\nDEL\r\n$7\r\ntestkey\r\n";
    let response = send_resp_command(&mut stream, del_cmd).await;
    assert_eq!(&response, b":1\r\n", "DEL should return 1 for deleted key");

    // DEL again - should return 0
    let response = send_resp_command(&mut stream, del_cmd).await;
    assert_eq!(&response, b":0\r\n", "DEL nonexistent should return 0");
}

#[tokio::test]
async fn test_exists_command() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // EXISTS on nonexistent key: *2\r\n$6\r\nEXISTS\r\n$5\r\nmykey\r\n
    let exists_cmd = b"*2\r\n$6\r\nEXISTS\r\n$5\r\nmykey\r\n";
    let response = send_resp_command(&mut stream, exists_cmd).await;
    assert_eq!(
        &response, b":0\r\n",
        "EXISTS should return 0 for nonexistent"
    );

    // SET the key
    let set_cmd = b"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n";
    send_resp_command(&mut stream, set_cmd).await;

    // EXISTS should now return 1
    let response = send_resp_command(&mut stream, exists_cmd).await;
    assert_eq!(
        &response, b":1\r\n",
        "EXISTS should return 1 for existing key"
    );
}

#[tokio::test]
async fn test_storage_commands_require_auth() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // Try SET without auth
    let set_cmd = b"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n";
    let response = send_resp_command(&mut stream, set_cmd).await;
    assert!(
        response.starts_with(b"-ERR") && String::from_utf8_lossy(&response).contains("NOAUTH"),
        "SET without AUTH should return NOAUTH error"
    );

    // Try GET without auth
    let get_cmd = b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
    let response = send_resp_command(&mut stream, get_cmd).await;
    assert!(
        response.starts_with(b"-ERR") && String::from_utf8_lossy(&response).contains("NOAUTH"),
        "GET without AUTH should return NOAUTH error"
    );
}

#[tokio::test]
async fn test_binary_data_storage() {
    let (_handle, port) = start_test_server().await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // SET binary data (null bytes): *3\r\n$3\r\nSET\r\n$6\r\nbinary\r\n$6\r\n\x00\x01\x02\xFF\xFE\xFD\r\n
    let set_cmd = b"*3\r\n$3\r\nSET\r\n$6\r\nbinary\r\n$6\r\n\x00\x01\x02\xFF\xFE\xFD\r\n";
    let response = send_resp_command(&mut stream, set_cmd).await;
    assert_eq!(&response, b"+OK\r\n");

    // GET binary data
    let get_cmd = b"*2\r\n$3\r\nGET\r\n$6\r\nbinary\r\n";
    let response = send_resp_command(&mut stream, get_cmd).await;
    assert_eq!(
        &response, b"$6\r\n\x00\x01\x02\xFF\xFE\xFD\r\n",
        "Should store and retrieve binary data correctly"
    );
}

#[tokio::test]
async fn test_lpush_and_llen() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // LPUSH first element
    let lpush_cmd = b"*3\r\n$5\r\nLPUSH\r\n$6\r\nmylist\r\n$5\r\nfirst\r\n";
    let response = send_resp_command(&mut stream, lpush_cmd).await;
    assert_eq!(&response, b":1\r\n", "First LPUSH should return length 1");

    // LPUSH second element
    let lpush_cmd = b"*3\r\n$5\r\nLPUSH\r\n$6\r\nmylist\r\n$6\r\nsecond\r\n";
    let response = send_resp_command(&mut stream, lpush_cmd).await;
    assert_eq!(&response, b":2\r\n", "Second LPUSH should return length 2");

    // LLEN
    let llen_cmd = b"*2\r\n$4\r\nLLEN\r\n$6\r\nmylist\r\n";
    let response = send_resp_command(&mut stream, llen_cmd).await;
    assert_eq!(&response, b":2\r\n", "LLEN should return 2");
}

#[tokio::test]
async fn test_lpush_and_rpop() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // LPUSH three elements
    send_resp_command(
        &mut stream,
        b"*3\r\n$5\r\nLPUSH\r\n$6\r\nmylist\r\n$5\r\nfirst\r\n",
    )
    .await;
    send_resp_command(
        &mut stream,
        b"*3\r\n$5\r\nLPUSH\r\n$6\r\nmylist\r\n$6\r\nsecond\r\n",
    )
    .await;
    send_resp_command(
        &mut stream,
        b"*3\r\n$5\r\nLPUSH\r\n$6\r\nmylist\r\n$5\r\nthird\r\n",
    )
    .await;

    // RPOP should return "first" (tail element)
    let rpop_cmd = b"*2\r\n$4\r\nRPOP\r\n$6\r\nmylist\r\n";
    let response = send_resp_command(&mut stream, rpop_cmd).await;
    assert_eq!(&response, b"$5\r\nfirst\r\n", "RPOP should return 'first'");

    // RPOP again should return "second"
    let response = send_resp_command(&mut stream, rpop_cmd).await;
    assert_eq!(
        &response, b"$6\r\nsecond\r\n",
        "RPOP should return 'second'"
    );

    // RPOP last element
    let response = send_resp_command(&mut stream, rpop_cmd).await;
    assert_eq!(&response, b"$5\r\nthird\r\n", "RPOP should return 'third'");

    // RPOP on empty list
    let response = send_resp_command(&mut stream, rpop_cmd).await;
    assert_eq!(
        &response, b"$-1\r\n",
        "RPOP on empty list should return nil"
    );
}

#[tokio::test]
async fn test_lrange() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // LPUSH three elements
    send_resp_command(
        &mut stream,
        b"*3\r\n$5\r\nLPUSH\r\n$6\r\nmylist\r\n$3\r\none\r\n",
    )
    .await;
    send_resp_command(
        &mut stream,
        b"*3\r\n$5\r\nLPUSH\r\n$6\r\nmylist\r\n$3\r\ntwo\r\n",
    )
    .await;
    send_resp_command(
        &mut stream,
        b"*3\r\n$5\r\nLPUSH\r\n$6\r\nmylist\r\n$5\r\nthree\r\n",
    )
    .await;

    // LRANGE 0 -1 (all elements)
    let lrange_cmd = b"*4\r\n$6\r\nLRANGE\r\n$6\r\nmylist\r\n$1\r\n0\r\n$2\r\n-1\r\n";
    let response = send_resp_command(&mut stream, lrange_cmd).await;
    assert_eq!(
        &response, b"*3\r\n$5\r\nthree\r\n$3\r\ntwo\r\n$3\r\none\r\n",
        "LRANGE should return all three elements in LPUSH order"
    );

    // LRANGE 0 1 (first two)
    let lrange_cmd = b"*4\r\n$6\r\nLRANGE\r\n$6\r\nmylist\r\n$1\r\n0\r\n$1\r\n1\r\n";
    let response = send_resp_command(&mut stream, lrange_cmd).await;
    assert_eq!(
        &response, b"*2\r\n$5\r\nthree\r\n$3\r\ntwo\r\n",
        "LRANGE 0 1 should return first two elements"
    );
}

#[tokio::test]
async fn test_brpop_immediate() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // LPUSH element
    send_resp_command(
        &mut stream,
        b"*3\r\n$5\r\nLPUSH\r\n$6\r\nmylist\r\n$5\r\nvalue\r\n",
    )
    .await;

    // BRPOP should return immediately
    let brpop_cmd = b"*3\r\n$5\r\nBRPOP\r\n$6\r\nmylist\r\n$1\r\n1\r\n";
    let response = send_resp_command(&mut stream, brpop_cmd).await;
    assert_eq!(
        &response, b"$5\r\nvalue\r\n",
        "BRPOP should return immediately"
    );
}

#[tokio::test]
async fn test_brpop_timeout() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // BRPOP on empty list with 1 second timeout
    let start = std::time::Instant::now();
    let brpop_cmd = b"*3\r\n$5\r\nBRPOP\r\n$6\r\nmylist\r\n$1\r\n1\r\n";
    let response = send_resp_command(&mut stream, brpop_cmd).await;
    let elapsed = start.elapsed();

    assert_eq!(&response, b"$-1\r\n", "BRPOP should timeout and return nil");
    assert!(
        elapsed >= std::time::Duration::from_secs(1),
        "BRPOP should wait at least 1 second"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(1500),
        "BRPOP should not wait much longer than timeout"
    );
}

#[tokio::test]
async fn test_llen_empty_list() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // LLEN on non-existent list
    let llen_cmd = b"*2\r\n$4\r\nLLEN\r\n$11\r\nnonexistent\r\n";
    let response = send_resp_command(&mut stream, llen_cmd).await;
    assert_eq!(&response, b":0\r\n", "LLEN on empty list should return 0");
}

#[tokio::test]
async fn test_hset_and_hget() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // HSET myhash field1 value1: *4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$6\r\nfield1\r\n$6\r\nvalue1\r\n
    let hset_cmd = b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$6\r\nfield1\r\n$6\r\nvalue1\r\n";
    let response = send_resp_command(&mut stream, hset_cmd).await;
    assert_eq!(&response, b":1\r\n", "HSET new field should return 1");

    // HGET myhash field1: *3\r\n$4\r\nHGET\r\n$6\r\nmyhash\r\n$6\r\nfield1\r\n
    let hget_cmd = b"*3\r\n$4\r\nHGET\r\n$6\r\nmyhash\r\n$6\r\nfield1\r\n";
    let response = send_resp_command(&mut stream, hget_cmd).await;
    assert_eq!(
        &response, b"$6\r\nvalue1\r\n",
        "HGET should return stored value"
    );
}

#[tokio::test]
async fn test_hget_nonexistent_field() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // HGET nonexistent hash/field
    let hget_cmd = b"*3\r\n$4\r\nHGET\r\n$11\r\nnonexistent\r\n$5\r\nfield\r\n";
    let response = send_resp_command(&mut stream, hget_cmd).await;
    assert_eq!(&response, b"$-1\r\n", "HGET nonexistent should return nil");
}

#[tokio::test]
async fn test_hset_update_field() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // HSET new field
    let hset_cmd = b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n$4\r\nold1\r\n";
    let response = send_resp_command(&mut stream, hset_cmd).await;
    assert_eq!(&response, b":1\r\n", "HSET new field should return 1");

    // HSET update same field
    let hset_cmd = b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n$4\r\nnew1\r\n";
    let response = send_resp_command(&mut stream, hset_cmd).await;
    assert_eq!(&response, b":0\r\n", "HSET update should return 0");

    // HGET should return new value
    let hget_cmd = b"*3\r\n$4\r\nHGET\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n";
    let response = send_resp_command(&mut stream, hget_cmd).await;
    assert_eq!(
        &response, b"$4\r\nnew1\r\n",
        "HGET should return updated value"
    );
}

#[tokio::test]
async fn test_hdel() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // HSET field
    let hset_cmd = b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n$5\r\nvalue\r\n";
    send_resp_command(&mut stream, hset_cmd).await;

    // HDEL field: *3\r\n$4\r\nHDEL\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n
    let hdel_cmd = b"*3\r\n$4\r\nHDEL\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n";
    let response = send_resp_command(&mut stream, hdel_cmd).await;
    assert_eq!(
        &response, b":1\r\n",
        "HDEL should return 1 for deleted field"
    );

    // HDEL again - should return 0
    let response = send_resp_command(&mut stream, hdel_cmd).await;
    assert_eq!(
        &response, b":0\r\n",
        "HDEL nonexistent field should return 0"
    );

    // HGET should return nil
    let hget_cmd = b"*3\r\n$4\r\nHGET\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n";
    let response = send_resp_command(&mut stream, hget_cmd).await;
    assert_eq!(
        &response, b"$-1\r\n",
        "HGET deleted field should return nil"
    );
}

#[tokio::test]
async fn test_hexists() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // HEXISTS nonexistent: *3\r\n$7\r\nHEXISTS\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n
    let hexists_cmd = b"*3\r\n$7\r\nHEXISTS\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n";
    let response = send_resp_command(&mut stream, hexists_cmd).await;
    assert_eq!(
        &response, b":0\r\n",
        "HEXISTS should return 0 for nonexistent field"
    );

    // HSET field
    let hset_cmd = b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n$5\r\nvalue\r\n";
    send_resp_command(&mut stream, hset_cmd).await;

    // HEXISTS should return 1
    let response = send_resp_command(&mut stream, hexists_cmd).await;
    assert_eq!(
        &response, b":1\r\n",
        "HEXISTS should return 1 for existing field"
    );
}

#[tokio::test]
async fn test_hlen() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // HLEN empty hash: *2\r\n$4\r\nHLEN\r\n$6\r\nmyhash\r\n
    let hlen_cmd = b"*2\r\n$4\r\nHLEN\r\n$6\r\nmyhash\r\n";
    let response = send_resp_command(&mut stream, hlen_cmd).await;
    assert_eq!(&response, b":0\r\n", "HLEN empty hash should return 0");

    // HSET three fields
    send_resp_command(
        &mut stream,
        b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$6\r\nfield1\r\n$6\r\nvalue1\r\n",
    )
    .await;
    send_resp_command(
        &mut stream,
        b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$6\r\nfield2\r\n$6\r\nvalue2\r\n",
    )
    .await;
    send_resp_command(
        &mut stream,
        b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$6\r\nfield3\r\n$6\r\nvalue3\r\n",
    )
    .await;

    // HLEN should return 3
    let response = send_resp_command(&mut stream, hlen_cmd).await;
    assert_eq!(&response, b":3\r\n", "HLEN should return 3");

    // HDEL one field
    send_resp_command(
        &mut stream,
        b"*3\r\n$4\r\nHDEL\r\n$6\r\nmyhash\r\n$6\r\nfield2\r\n",
    )
    .await;

    // HLEN should return 2
    let response = send_resp_command(&mut stream, hlen_cmd).await;
    assert_eq!(&response, b":2\r\n", "HLEN after delete should return 2");
}

#[tokio::test]
async fn test_hgetall() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // HGETALL empty hash: *2\r\n$7\r\nHGETALL\r\n$6\r\nmyhash\r\n
    let hgetall_cmd = b"*2\r\n$7\r\nHGETALL\r\n$6\r\nmyhash\r\n";
    let response = send_resp_command(&mut stream, hgetall_cmd).await;
    assert_eq!(
        &response, b"*0\r\n",
        "HGETALL empty hash should return empty array"
    );

    // HSET two fields
    send_resp_command(
        &mut stream,
        b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$4\r\nkey1\r\n$6\r\nvalue1\r\n",
    )
    .await;
    send_resp_command(
        &mut stream,
        b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$4\r\nkey2\r\n$6\r\nvalue2\r\n",
    )
    .await;

    // HGETALL should return all fields and values
    let response = send_resp_command(&mut stream, hgetall_cmd).await;
    let response_str = String::from_utf8_lossy(&response);
    assert!(
        response_str.starts_with("*4\r\n"),
        "HGETALL should return array of 4 elements (2 fields + 2 values)"
    );
    assert!(
        response_str.contains("key1") && response_str.contains("value1"),
        "HGETALL should include key1/value1"
    );
    assert!(
        response_str.contains("key2") && response_str.contains("value2"),
        "HGETALL should include key2/value2"
    );
}

#[tokio::test]
async fn test_hash_isolation() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // HSET hash1 field value1
    send_resp_command(
        &mut stream,
        b"*4\r\n$4\r\nHSET\r\n$5\r\nhash1\r\n$5\r\nfield\r\n$6\r\nvalue1\r\n",
    )
    .await;

    // HSET hash2 field value2
    send_resp_command(
        &mut stream,
        b"*4\r\n$4\r\nHSET\r\n$5\r\nhash2\r\n$5\r\nfield\r\n$6\r\nvalue2\r\n",
    )
    .await;

    // HGET hash1 field should return value1
    let hget_cmd = b"*3\r\n$4\r\nHGET\r\n$5\r\nhash1\r\n$5\r\nfield\r\n";
    let response = send_resp_command(&mut stream, hget_cmd).await;
    assert_eq!(&response, b"$6\r\nvalue1\r\n", "hash1 should have value1");

    // HGET hash2 field should return value2
    let hget_cmd = b"*3\r\n$4\r\nHGET\r\n$5\r\nhash2\r\n$5\r\nfield\r\n";
    let response = send_resp_command(&mut stream, hget_cmd).await;
    assert_eq!(&response, b"$6\r\nvalue2\r\n", "hash2 should have value2");
}

#[tokio::test]
async fn test_hash_binary_values() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // HSET with binary data: *4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$6\r\nbinary\r\n$6\r\n\x00\x01\x02\xFF\xFE\xFD\r\n
    let hset_cmd =
        b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$6\r\nbinary\r\n$6\r\n\x00\x01\x02\xFF\xFE\xFD\r\n";
    let response = send_resp_command(&mut stream, hset_cmd).await;
    assert_eq!(&response, b":1\r\n");

    // HGET binary data
    let hget_cmd = b"*3\r\n$4\r\nHGET\r\n$6\r\nmyhash\r\n$6\r\nbinary\r\n";
    let response = send_resp_command(&mut stream, hget_cmd).await;
    assert_eq!(
        &response, b"$6\r\n\x00\x01\x02\xFF\xFE\xFD\r\n",
        "Should store and retrieve binary data correctly"
    );
}

#[tokio::test]
async fn test_hash_job_metadata_use_case() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // Simulate job lifecycle
    // HSET job:123 status pending
    send_resp_command(
        &mut stream,
        b"*4\r\n$4\r\nHSET\r\n$7\r\njob:123\r\n$6\r\nstatus\r\n$7\r\npending\r\n",
    )
    .await;

    // HSET job:123 created_at 1234567890
    send_resp_command(
        &mut stream,
        b"*4\r\n$4\r\nHSET\r\n$7\r\njob:123\r\n$10\r\ncreated_at\r\n$10\r\n1234567890\r\n",
    )
    .await;

    // Update status to running
    send_resp_command(
        &mut stream,
        b"*4\r\n$4\r\nHSET\r\n$7\r\njob:123\r\n$6\r\nstatus\r\n$7\r\nrunning\r\n",
    )
    .await;

    // Add stdout
    send_resp_command(
        &mut stream,
        b"*4\r\n$4\r\nHSET\r\n$7\r\njob:123\r\n$6\r\nstdout\r\n$12\r\nHello World!\r\n",
    )
    .await;

    // Check status
    let hget_cmd = b"*3\r\n$4\r\nHGET\r\n$7\r\njob:123\r\n$6\r\nstatus\r\n";
    let response = send_resp_command(&mut stream, hget_cmd).await;
    assert_eq!(&response, b"$7\r\nrunning\r\n");

    // Get all job metadata
    let hgetall_cmd = b"*2\r\n$7\r\nHGETALL\r\n$7\r\njob:123\r\n";
    let response = send_resp_command(&mut stream, hgetall_cmd).await;
    let response_str = String::from_utf8_lossy(&response);

    assert!(response_str.starts_with("*6\r\n"), "Should have 6 elements");
    assert!(response_str.contains("status"));
    assert!(response_str.contains("running"));
    assert!(response_str.contains("created_at"));
    assert!(response_str.contains("stdout"));
    assert!(response_str.contains("Hello World!"));
}

// Security tests for hash operations
#[tokio::test]
async fn test_hash_requires_auth() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // Try HSET without auth
    let hset_cmd = b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n$5\r\nvalue\r\n";
    let response = send_resp_command(&mut stream, hset_cmd).await;
    assert!(
        response.starts_with(b"-ERR") && String::from_utf8_lossy(&response).contains("NOAUTH"),
        "HSET without AUTH should return NOAUTH error"
    );

    // Try HGET without auth
    let hget_cmd = b"*3\r\n$4\r\nHGET\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n";
    let response = send_resp_command(&mut stream, hget_cmd).await;
    assert!(
        response.starts_with(b"-ERR") && String::from_utf8_lossy(&response).contains("NOAUTH"),
        "HGET without AUTH should return NOAUTH error"
    );
}

#[tokio::test]
async fn test_hash_invalid_arguments() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // HSET with too few arguments
    let hset_cmd = b"*3\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n";
    let response = send_resp_command(&mut stream, hset_cmd).await;
    assert!(
        response.starts_with(b"-ERR"),
        "HSET with too few arguments should return error"
    );

    // HGET with too many arguments
    let hget_cmd = b"*4\r\n$4\r\nHGET\r\n$6\r\nmyhash\r\n$5\r\nfield\r\n$5\r\nextra\r\n";
    let response = send_resp_command(&mut stream, hget_cmd).await;
    assert!(
        response.starts_with(b"-ERR"),
        "HGET with too many arguments should return error"
    );

    // HDEL with too few arguments
    let hdel_cmd = b"*2\r\n$4\r\nHDEL\r\n$6\r\nmyhash\r\n";
    let response = send_resp_command(&mut stream, hdel_cmd).await;
    assert!(
        response.starts_with(b"-ERR"),
        "HDEL with too few arguments should return error"
    );

    // HLEN with too many arguments
    let hlen_cmd = b"*3\r\n$4\r\nHLEN\r\n$6\r\nmyhash\r\n$5\r\nextra\r\n";
    let response = send_resp_command(&mut stream, hlen_cmd).await;
    assert!(
        response.starts_with(b"-ERR"),
        "HLEN with too many arguments should return error"
    );
}

#[tokio::test]
async fn test_hash_field_name_injection() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // Try field names with special characters that could be injection attempts
    // Field with colon (used internally as separator)
    let hset_cmd = b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$10\r\nfield:test\r\n$5\r\nvalue\r\n";
    let response = send_resp_command(&mut stream, hset_cmd).await;
    assert_eq!(
        &response, b":1\r\n",
        "Field with colon should be allowed (properly escaped)"
    );

    // Verify it can be retrieved
    let hget_cmd = b"*3\r\n$4\r\nHGET\r\n$6\r\nmyhash\r\n$10\r\nfield:test\r\n";
    let response = send_resp_command(&mut stream, hget_cmd).await;
    assert_eq!(
        &response, b"$5\r\nvalue\r\n",
        "Field with colon should be retrievable"
    );

    // Verify hash isolation (field:test shouldn't leak to other hashes)
    let hget_cmd2 = b"*3\r\n$4\r\nHGET\r\n$9\r\notherhash\r\n$10\r\nfield:test\r\n";
    let response = send_resp_command(&mut stream, hget_cmd2).await;
    assert_eq!(
        &response, b"$-1\r\n",
        "Field should not exist in other hashes"
    );
}

#[tokio::test]
async fn test_hash_large_values() {
    let (_handle, port) = start_test_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("Failed to connect");

    // AUTH first
    let auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$32\r\ntest_session_key_32_bytes_long!!\r\n";
    send_resp_command(&mut stream, auth_cmd).await;

    // Test with reasonably large value (100KB)
    let large_value = vec![b'X'; 100_000];
    let value_len = format!("{}", large_value.len());

    // Construct HSET command
    let mut hset_cmd = Vec::new();
    hset_cmd.extend_from_slice(b"*4\r\n$4\r\nHSET\r\n$6\r\nmyhash\r\n$5\r\nlarge\r\n$");
    hset_cmd.extend_from_slice(value_len.as_bytes());
    hset_cmd.extend_from_slice(b"\r\n");
    hset_cmd.extend_from_slice(&large_value);
    hset_cmd.extend_from_slice(b"\r\n");

    let response = send_resp_command(&mut stream, &hset_cmd).await;
    assert_eq!(
        &response, b":1\r\n",
        "Should handle large values (within reasonable limits)"
    );

    // Verify retrieval
    let hget_cmd = b"*3\r\n$4\r\nHGET\r\n$6\r\nmyhash\r\n$5\r\nlarge\r\n";
    stream.write_all(hget_cmd).await.expect("Failed to write");

    // Read response (need larger buffer)
    let mut response = vec![0u8; 150_000];
    let n = stream.read(&mut response).await.expect("Failed to read");
    response.truncate(n);

    // Verify bulk string header
    assert!(
        response.starts_with(b"$100000\r\n"),
        "Should return correct bulk string length"
    );
}
