use asndb::store::IPDatabase;
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_load_from_tsv(c: &mut Criterion) {
    let path = "./ip2asn-combined.tsv"; // Update with your TSV file path

    c.bench_function("Load from TSV", |b| {
        b.iter(|| {
            let mut db = IPDatabase::new();
            db.load_from_tsv(path).unwrap();
        });
    });
}

fn bench_save_to_binary(c: &mut Criterion) {
    let path = "./ip2asn-combined.tsv"; // Update with your TSV file path
    let binary_path = "./ip_database.bin";

    c.bench_function("Save to binary", |b| {
        b.iter(|| {
            let mut db = IPDatabase::new();
            db.load_from_tsv(path).unwrap();
            db.save_to_file(binary_path).unwrap();
        });
    });
}

fn bench_load_from_binary(c: &mut Criterion) {
    let binary_path = "./ip_database.bin";

    c.bench_function("Load from binary", |b| {
        b.iter(|| {
            IPDatabase::load_from_file(binary_path).unwrap();
        });
    });
}

fn bench_query_ip(c: &mut Criterion) {
    let binary_path = "./ip_database.bin";
    let ip_to_query = "51.79.162.201"; // Replace with the IP you want to query
    let db = IPDatabase::load_from_file(binary_path).unwrap();

    c.bench_function("Query IP", |b| {
        b.iter(|| {
            db.query(ip_to_query);
        });
    });
}

criterion_group!(
    benches,
    bench_load_from_tsv,
    bench_save_to_binary,
    bench_load_from_binary,
    bench_query_ip
);
criterion_main!(benches);
