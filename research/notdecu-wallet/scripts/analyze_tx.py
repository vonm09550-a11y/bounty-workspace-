#!/usr/bin/env python3
"""2.2 offline analysis of the Helius-parsed transactions. Prints tables for 03-enrichment.md."""
import duckdb, os
DB=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','data','notdecu.duckdb')
W="4vw54BmAogeRV3vPKWyFet5yf8DTLcREzdSzx4rw9Ud9"
JITO={'96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5','HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe','Cw8CFyvC5FHnEsoHY1eZp6NRW7SqJQsT1LFfw2ZzpQcv','ADaUMid9yfUytqMBgopwjb2DTLSokTSzL1zt6iGPaS49','DfXygSm4jCyNCybVYYK6DwvWqjKee8pbDmJGcLWNDXjh','ADuUkR4vqLUMWXxW9gh6D6L8pMSawimctcNZ5pGwDcEt','DttWaMuVvTiduZRnguLF7jNxTgiMBZ1hyAumKUiL2KRL','3AVi9Tg9Uo68tJfuvoKvqKNWKkC5wPdSSdeBnizKZ6jT'}
con=duckdb.connect(DB, read_only=True)
def show(title, sql):
    print(f"\n## {title}\n"); print(con.execute(sql).df().to_string(index=False))
show("coverage: trade tx missing from parsed", f"select count(distinct tx_hash) missing from activity where tx_hash not in (select signature from tx)")
show("router (top-level program) by month, trade tx only", f"""
with t as (select p.signature, p.program, strftime(x.t,'%Y-%m') m from tx_programs p join tx x using(signature)
           where p.depth='top' and x.fee_payer='{W}' and p.signature in (select tx_hash from activity)
           and p.program not in ('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL','TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb','TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'))
select m, program, count(*) c from t group by 1,2 order by 1, c desc""")
show("venue (Helius source) by month, trade tx", f"""select strftime(t,'%Y-%m') m, source, count(*) c from tx where signature in (select tx_hash from activity) group by 1,2 order by 1, c desc""")
show("inner programs of interest by month", f"""
select strftime(x.t,'%Y-%m') m,
 sum((p.program='Gz9VPiSLQYbvKyb3jZPjNfyA6n4T4qVFUuAukgL964nL')::int) Gz9V, sum((p.program='F5tfvbLog9VdGUPqBDTT8rgXvTTcq7e5UiGnupL1zvBq')::int) F5tf,
 sum((p.program='ExA6GYhHAeRNMWVNLrDir1SKPJZcZA2oaPq6uriSmxfJ')::int) ExA6, sum((p.program='JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4')::int) JUP,
 sum((p.program='LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo')::int) meteora, sum((p.program='675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8')::int) ray_v4,
 sum((p.program='CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK')::int) ray_clmm
from tx_programs p join tx x using(signature) where x.signature in (select tx_hash from activity) group by 1 order by 1""")
show("SOL leaving the wallet: top recipients (trade tx)", f"""
select to_account, count(*) c, round(sum(sol),2) sol, round(median(sol),5) med_sol, min(strftime(x.t,'%Y-%m')) first_m, max(strftime(x.t,'%Y-%m')) last_m
from tx_native_out n join tx x using(signature) where x.signature in (select tx_hash from activity) group by 1 order by c desc limit 14""")
jito=",".join(f"'{a}'" for a in JITO)
show("Jito tips by month", f"""select strftime(x.t,'%Y-%m') m, count(*) tips, round(sum(sol),2) sol, round(median(sol),5) med from tx_native_out n join tx x using(signature) where n.to_account in ({jito}) group by 1 order by 1""")
show("base fee (lamports) by month", f"""select strftime(t,'%Y-%m') m, count(*) c, round(median(fee)) med_fee, round(quantile_cont(fee,0.9)) p90_fee from tx where fee_payer='{W}' and signature in (select tx_hash from activity) group by 1 order by 1""")
show("his trade tx per slot", f"""select n_per_slot, count(*) slots from (select slot, count(*) n_per_slot from tx where fee_payer='{W}' and signature in (select tx_hash from activity) group by 1) group by 1 order by 1 limit 10""")
show("transfer tx: types and fee payer", f"""select type, source, (fee_payer='{W}') mine, count(*) c from tx where signature in (select tx_hash from transfers) and signature not in (select tx_hash from activity) group by 1,2,3 order by c desc limit 10""")
show("transfers to 4hQZ: tx type, fee payer, top programs", f"""
select x.type, x.source, (x.fee_payer='{W}') mine, count(*) c from transfers tr join tx x on x.signature=tr.tx_hash
where tr.to_address='4hQZ1GtLTvAzetszCcWrb8zxiuVvEt85Bb7y6VNzA2ve' group by 1,2,3 order by c desc""")
show("programs in 4hQZ transfer tx", f"""select p.program, p.depth, count(*) c from transfers tr join tx_programs p on p.signature=tr.tx_hash where tr.to_address='4hQZ1GtLTvAzetszCcWrb8zxiuVvEt85Bb7y6VNzA2ve' group by 1,2 order by c desc limit 8""")
show("are 4hQZ transfer tx also trade tx?", f"""select count(distinct tr.tx_hash) total, count(distinct case when tr.tx_hash in (select tx_hash from activity) then tr.tx_hash end) also_trade from transfers tr where tr.to_address='4hQZ1GtLTvAzetszCcWrb8zxiuVvEt85Bb7y6VNzA2ve'""")
