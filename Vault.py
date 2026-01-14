import blackboxprotobuf
import gzip
import io
import copy
import os
from mitmproxy import http
from mitmproxy.tools.main import mitmweb

ID_FILE  = "items.txt"
URL_BACKPACK = "GetBackPack"

def load_items():
    if not os.path.exists(ID_FILE):
        with open(ID_FILE, "w") as f: f.write("203000014\n")
        return [203000014]
    with open(ID_FILE, "r") as f:
        return [int(line.replace(",","").strip()) for line in f if line.strip().isdigit()]

def get_data(f):
    d = f.response.content
    if f.response.headers.get("Content-Encoding") == "gzip" or (len(d)>2 and d[:2]==b'\x1f\x8b'):
        try:
            b = io.BytesIO(d)
            with gzip.GzipFile(fileobj=b) as z: d = z.read()
        except: pass
    return d

def set_data(f, d):
    final_payload = bytes(d) 
    if "Content-Encoding" in f.response.headers: 
        del f.response.headers["Content-Encoding"]
    f.response.content = final_payload
    f.response.headers["Content-Length"] = str(len(final_payload))

class CollectionInjector:
    def response(self, flow: http.HTTPFlow) -> None:
        if URL_BACKPACK.lower() in flow.request.path.lower():
            data = get_data(flow)
            try:
                msg, typedef = blackboxprotobuf.decode_message(data)
                if '3' in msg and isinstance(msg['3'], list) and len(msg['3']) > 0:
                    tpl = msg['3'][0]
                    exist = set(i.get('1') for i in msg['3'] if '1' in i)
                    ids = load_items()
                    
                    count = 0
                    for i in ids:
                        if i not in exist:
                            new = copy.deepcopy(tpl)
                            new['1'] = int(i)
                            new['2'] = 1
                            new['4'] = -1
                            msg['3'].append(new)
                            count += 1
                    
                    if count > 0:
                        print(f"[COLLECTION] Injected {count} new items into backpack.")
                        try:
                            typedef['3']['message_typedef']['1']['type'] = 'int'
                            typedef['3']['message_typedef']['2']['type'] = 'int'
                            typedef['3']['message_typedef']['4']['type'] = 'int'
                        except: pass
                        new_d = blackboxprotobuf.encode_message(msg, typedef)
                        set_data(flow, new_d)
            except Exception as e:
                print(f"[ERROR] Failed to inject items: {e}")

addons = [CollectionInjector()]

if __name__ == "__main__":
    mitmweb([
        "-s", __file__,
        "-p", "9791",
        "--set", "block_global=false"
    ])
