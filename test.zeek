@load base/frameworks/sumstats

global stat_dict:table[addr] of count = table();

const count_404_resp = 2;
const resp_404_ratio = 0.2;
const entropy_resp = 0.5;


event zeek_init() {
    local r1 = SumStats::Reducer($stream="http.scan", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="http.scan.attacker",
                      $epoch=12.2mins,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
                        local r = result["http.scan"];
                        if(r$num > count_404_resp) {
                        	if(r$num * 10 / stat_dict[key$host] > resp_404_ratio * 10) {
                        		if(r$unique * 10 / r$num > entropy_resp * 10) {
                        			print fmt("%s is a scanner with %d scan attempts on %d urls",key$host,r$num,r$unique);
                        		}
                        	}
                        }
                        stat_dict[key$host] = 0;
                      },
                      $epoch_finished(ts:time) = {
                    	stat_dict = table();
                      }]);
}

event http_reply(c: connection, version: string, code: count, reason: string) {
	if(c$id$orig_h in stat_dict) {
		stat_dict[c$id$orig_h] += 1;
	}
	else {
		stat_dict[c$id$orig_h] = 1;
	}
	if(code == 404) {
		SumStats::observe("http.scan", [$host=c$id$orig_h], [$str=fmt("%s%s",c$http$host,c$http$uri)]);
	}
}
