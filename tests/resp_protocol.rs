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
    assert_eq!(&response, b":0\r\n", "EXISTS should return 0 for nonexistent");

    // SET the key
    let set_cmd = b"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n";
    send_resp_command(&mut stream, set_cmd).await;

    // EXISTS should now return 1
    let response = send_resp_command(&mut stream, exists_cmd).await;
    assert_eq!(&response, b":1\r\n", "EXISTS should return 1 for existing key");
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
        &response,
        b"$6\r\n\x00\x01\x02\xFF\xFE\xFD\r\n",
        "Should store and retrieve binary data correctly"
    );
}
