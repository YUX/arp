use arp_common::frame::Frame;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

fn bench_route_serialize(c: &mut Criterion) {
    let dest = [0x42u8; 32];
    let payload = vec![0xABu8; 1024];
    let frame = Frame::route(&dest, &payload);

    c.bench_function("route_serialize_1kb", |b| {
        b.iter(|| black_box(frame.serialize()));
    });
}

fn bench_route_parse(c: &mut Criterion) {
    let dest = [0x42u8; 32];
    let payload = vec![0xABu8; 1024];
    let frame = Frame::route(&dest, &payload);
    let serialized = frame.serialize();

    c.bench_function("route_parse_1kb", |b| {
        b.iter(|| black_box(Frame::parse(&serialized).unwrap()));
    });
}

fn bench_deliver_serialize(c: &mut Criterion) {
    let src = [0x42u8; 32];
    let payload = vec![0xABu8; 1024];
    let frame = Frame::deliver(&src, &payload);

    c.bench_function("deliver_serialize_1kb", |b| {
        b.iter(|| black_box(frame.serialize()));
    });
}

fn bench_deliver_parse(c: &mut Criterion) {
    let src = [0x42u8; 32];
    let payload = vec![0xABu8; 1024];
    let frame = Frame::deliver(&src, &payload);
    let serialized = frame.serialize();

    c.bench_function("deliver_parse_1kb", |b| {
        b.iter(|| black_box(Frame::parse(&serialized).unwrap()));
    });
}

fn bench_challenge_roundtrip(c: &mut Criterion) {
    let challenge = [0xABu8; 32];
    let server_pubkey = [0xCDu8; 32];
    let frame = Frame::challenge(&challenge, &server_pubkey, 0x10);

    c.bench_function("challenge_roundtrip", |b| {
        b.iter(|| {
            let bytes = frame.serialize();
            black_box(Frame::parse(&bytes).unwrap())
        });
    });
}

fn bench_status_serialize(c: &mut Criterion) {
    let ref_pubkey = [0x42u8; 32];
    let frame = Frame::status(&ref_pubkey, 0x01);

    c.bench_function("status_serialize", |b| {
        b.iter(|| black_box(frame.serialize()));
    });
}

fn bench_route_max_payload(c: &mut Criterion) {
    let dest = [0x42u8; 32];
    let payload = vec![0xABu8; 65535];
    let frame = Frame::route(&dest, &payload);

    c.bench_function("route_serialize_64kb", |b| {
        b.iter(|| black_box(frame.serialize()));
    });
}

fn bench_serialize_deliver_direct(c: &mut Criterion) {
    let src = [0x42u8; 32];
    let payload = vec![0xABu8; 1024];

    c.bench_function("serialize_deliver_direct_1kb", |b| {
        b.iter(|| black_box(Frame::serialize_deliver(&src, &payload)));
    });
}

criterion_group!(
    benches,
    bench_route_serialize,
    bench_route_parse,
    bench_deliver_serialize,
    bench_deliver_parse,
    bench_challenge_roundtrip,
    bench_status_serialize,
    bench_route_max_payload,
    bench_serialize_deliver_direct,
);
criterion_main!(benches);
