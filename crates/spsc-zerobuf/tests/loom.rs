#![cfg(loom)]

use loom::future::block_on;
use loom::model;
use loom::thread::spawn;
use tracing::info;

use onioncloud_spsc_zerobuf::new;

#[test]
fn test_send_recv() {
    model(|| {
        let (mut send, mut recv) = new::<Box<u64>>();

        info!("start");

        spawn(move || {
            block_on(async move {
                for i in 0..3 {
                    send.feed(Box::new(i)).await.unwrap();
                    info!("sent {i}");
                }
                send.close().await.unwrap();
                info!("send finished");
            })
        });

        block_on(async move {
            for i in 0..3 {
                let v = recv.next().await;
                info!("received");
                assert_eq!(v.as_deref(), Some(&i));
            }
            assert_eq!(recv.next().await, None);
            info!("receive finished");
        });
    });
}
