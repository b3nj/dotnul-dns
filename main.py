from flask import Flask, jsonify
import dns.resolver

app = Flask(__name__)

@app.route('/api/dns/<domain>')
def resolveany(domain):
    toreturn = {}
    request = dns.message.make_query(domain, "ANY", "IN", use_edns=False, want_dnssec=True)
    answer =  dns.query.udp_with_fallback(request, "8.8.8.8", timeout=2)
    for rrsets in answer:
      if type(rrsets) == dns.message.QueryMessage:
        for rr in rrsets.answer:
          for rdata in rr:
            if dns.rdatatype.to_text(rdata.rdtype) not in toreturn:
              toreturn[dns.rdatatype.to_text(rdata.rdtype)] = []
            toreturn[dns.rdatatype.to_text(rdata.rdtype)].append(rdata.to_text())
    return jsonify(toreturn)

@app.route('/api/dns/<domain>/<qtype>')
def resolvetype(domain, qtype):
    toreturn = {}
    request = dns.message.make_query(domain, qtype, "IN", use_edns=False, want_dnssec=True)
    answer =  dns.query.udp_with_fallback(request, "8.8.8.8", timeout=2)
    for rrsets in answer:
      if type(rrsets) == dns.message.QueryMessage:
        for rr in rrsets.answer:
          for rdata in rr:
            if dns.rdatatype.to_text(rdata.rdtype) not in toreturn:
              toreturn[dns.rdatatype.to_text(rdata.rdtype)] = []
            toreturn[dns.rdatatype.to_text(rdata.rdtype)].append(rdata.to_text())
    return jsonify(toreturn)

@app.route('/api/dns/<domain>/<qtype>/<nameserver>')
def resolvetypens(domain, qtype, nameserver):
    toreturn = {}
    request = dns.message.make_query(domain, qtype, "IN", use_edns=False, want_dnssec=True)
    answer =  dns.query.udp_with_fallback(request, nameserver, timeout=2)
    for rrsets in answer:
      if type(rrsets) == dns.message.QueryMessage:
        for rr in rrsets.answer:
          for rdata in rr:
            if dns.rdatatype.to_text(rdata.rdtype) not in toreturn:
              toreturn[dns.rdatatype.to_text(rdata.rdtype)] = []
            toreturn[dns.rdatatype.to_text(rdata.rdtype)].append(rdata.to_text())
    return jsonify(toreturn)

@app.route('/api/dns/<domain>/<qtype>/<nameserver>/tls')
def resolvetls(domain, qtype, nameserver):
    toreturn = {}
    request = dns.message.make_query(domain, qtype, "IN", use_edns=False, want_dnssec=True)
    rrsets =  dns.query.tls(request, nameserver, timeout=2)
    if type(rrsets) == dns.message.QueryMessage:
      for rr in rrsets.answer:
        for rdata in rr:
          if dns.rdatatype.to_text(rdata.rdtype) not in toreturn:
            toreturn[dns.rdatatype.to_text(rdata.rdtype)] = []
          toreturn[dns.rdatatype.to_text(rdata.rdtype)].append(rdata.to_text())
    return jsonify(toreturn)

@app.route('/api/dns/<domain>/<qtype>/<nameserver>/https')
def resolvehttps(domain, qtype, nameserver):
    toreturn = {}
    request = dns.message.make_query(domain, qtype, "IN", use_edns=False, want_dnssec=True)
    rrsets =  dns.query.https(request, nameserver, timeout=2)
    if type(rrsets) == dns.message.QueryMessage:
      for rr in rrsets.answer:
        for rdata in rr:
          if dns.rdatatype.to_text(rdata.rdtype) not in toreturn:
            toreturn[dns.rdatatype.to_text(rdata.rdtype)] = []
          toreturn[dns.rdatatype.to_text(rdata.rdtype)].append(rdata.to_text())
    return jsonify(toreturn)

