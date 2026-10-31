use iam::spiffe::SpiffeId;

fn main() {
    let svid = SpiffeId::parse("spiffe://td1/agent/a1/task/t1").unwrap();
    println!("{}", svid.workload_path());
    let svid2 = SpiffeId::parse("spiffe://td1/agent/a1/task/t1/subagent/s1/task/c1").unwrap();
    println!("{}", svid2.workload_path());
}
