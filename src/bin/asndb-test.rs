use asndb::store::IPDatabase;
use std::{io, time::Instant};

fn main() -> io::Result<()> {
    let start_time = Instant::now(); // Start timing
    let mut db = IPDatabase::new();
    let path = "./ip2asn-combined.tsv"; // Update with your TSV file path

    // Load from TSV and check time
    let load_start_time = Instant::now();
    db.load_from_tsv(path)?;
    let load_duration = load_start_time.elapsed();
    println!("Time to load TSV: {:?}", load_duration);

    // Save the database to a binary file and check time
    let binary_path = "./ip_database.bin"; // Path to save the binary file
    let save_start_time = Instant::now();
    db.save_to_file(binary_path)?;
    let save_duration = save_start_time.elapsed();
    println!("Time to save binary file: {:?}", save_duration);

    // Load the database from the binary file and check time
    let load_from_file_start_time = Instant::now();
    let loaded_db = IPDatabase::load_from_file(binary_path)?;
    let load_from_file_duration = load_from_file_start_time.elapsed();
    println!(
        "Time to load from binary file: {:?}",
        load_from_file_duration
    );

    // Example query and check time
    let ip_to_query = "51.79.162.201"; // Replace with the IP you want to query
    let query_start_time = Instant::now();
    let response = loaded_db.query(ip_to_query);
    let query_duration = query_start_time.elapsed();
    println!("Time to query: {:?}", query_duration);
    println!("Response: {:?}", response); // Show response

    let total_duration = start_time.elapsed(); // Calculate total elapsed time
    println!("Total elapsed time: {:?}", total_duration); // Print total elapsed time

    Ok(())
}
