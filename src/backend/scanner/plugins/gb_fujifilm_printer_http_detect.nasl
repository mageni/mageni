# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170522");
  script_version("2023-08-08T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-08-08 05:06:11 +0000 (Tue, 08 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-07-28 11:23:26 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Fuji Xerox / Fujifilm Printer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  # nb: Don't use e.g. webmirror.nasl or DDI_Directory_Scanner.nasl as this VT should
  # run as early as possible so that the printer can be early marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Fuji Xerox / Fujifilm printer devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("fujifilm_printers.inc");
include("dump.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = http_get_port(default: 80);

urls = get_fujifilm_detect_urls();

foreach url (keys(urls)) {

  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");

  buf = http_get_cache(item: url, port: port);

  if (!buf || (buf !~ "^HTTP/1\.[01] 200" && buf !~ "^HTTP/1\.[01] 401"))
    continue;

  # Replace non-printable characters to avoid language based false-negatives
  buf = bin2string(ddata: buf, noprint_replacement: "");

  if (match = eregmatch(pattern: pattern, string: buf, icase: TRUE)) {
    if (isnull(match[1]))
      continue;

    concl = "    " + match[0];
    conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    version = "unknown";

    if ("FUJIFILM Business Innovation Corp" >< pattern) {
      url = "/ews/Management/Anonymous/StatusConfig";
      headers = make_array("Content-Type", "text/xml;",
                           "soapAction", "http://www.PGS4005SGP.co.jp/2003/12/ssm/management/statusConfig#GetAttribute",
                           "X-Requested-With", "XMLHttpRequest");
      data = '<?xml version="1.0" encoding="utf-8" ?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
             '<soap:Header><msg:MessageInformation xmlns:msg="http://www.PGS4005SGP.co.jp/2014/08/ssm/management/message">' +
             '<msg:MessageExchangeType>RequestResponse</msg:MessageExchangeType>' +
             '<msg:MessageType>Request</msg:MessageType><msg:Action>http://www.PGS4005SGP.co.jp/2003/12/ssm/management/statusConfig#GetAttribute</msg:Action>' +
             '<msg:From><msg:Address>http://www.PGS4005SGP.co.jp/2014/08/ssm/management/soap/epr/client</msg:Address><msg:ReferenceParameters/>' +
             '</msg:From><msg:Locale>en-US</msg:Locale></msg:MessageInformation></soap:Header>' +
             '<soap:Body><cfg:GetAttribute xmlns:cfg="http://www.PGS4005SGP.co.jp/2003/12/ssm/management/statusConfig">' +
             '<cfg:Object name="urn:PGS4005SGP:names:ssm:1.0:management:root" offset="0"/>' +
             '</cfg:GetAttribute></soap:Body></soap:Envelope>';
      req = http_post_put_req(port: port, url: url, data: data, add_headers: headers, referer_url: "/home/index.html");
      # nb: Don't use http_keepalive_send_recv() since we get a nested response
      res = http_send_recv(port: port, data: req);

      if (!res || (res !~ "^HTTP/1\.[01] 200" && res !~ "^HTTP/1\.[01] 401"))
        continue;
      res = bin2string(ddata: res, noprint_replacement: "");
      # <Attribute name="Name" type="string">ApeosPrint C325/328 dw</Attribute>
      mod = eregmatch(pattern: '"Name"[^>]+>(Apeos[^<]+)', string: res);
      if (!isnull(mod[1])) {
        concl += '\n    ' + mod[0];
        conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        model = mod[1];
      }
      # <Attribute name="Version" type="string">202105251727</Attribute>
      vers = eregmatch(pattern: '"Version"[^>]+>([0-9]+)', string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concl += '\n    ' + vers[0];
      }
    } else if ("Fuji Xerox Asset Tag" >< pattern) {
      url = "/ssm/Management/Anonymous/StatusConfig";
      headers = make_array("Content-Type", "text/xml;",
                           "soapAction", '"http://www.fujixerox.co.jp/2003/12/ssm/management/statusConfig#GetAttribute"',
                           "X-Requested-With", "XMLHttpRequest");
      data = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
             '<soap:Header><msg:MessageInformation xmlns:msg="http://www.fujixerox.co.jp/2014/08/ssm/management/message">' +
             '<msg:MessageExchangeType>RequestResponse</msg:MessageExchangeType>' +
             '<msg:MessageType>Request</msg:MessageType><msg:Action>http://www.fujixerox.co.jp/2003/12/ssm/management/statusConfig#GetAttribute</msg:Action>' +
             '<msg:From><msg:Address>http://www.fujixerox.co.jp/2014/08/ssm/management/soap/epr/client</msg:Address><msg:ReferenceParameters/>' +
             '</msg:From></msg:MessageInformation></soap:Header>' +
             '<soap:Body><cfg:GetAttribute xmlns:cfg="http://www.fujixerox.co.jp/2003/12/ssm/management/statusConfig">' +
             '<cfg:Object name="urn:fujixerox:names:ssm:1.0:management:ProductName" offset="0"/>' +
             '<cfg:Object name="urn:fujixerox:names:ssm:1.0:management:GRSFirmwareWatchStatus" offset="0"/>' +
             '</cfg:GetAttribute></soap:Body></soap:Envelope>';
      req = http_post_put_req(port: port, url: url, data: data, add_headers: headers, referer_url: "/home/index.html");

      # nb: Don't use http_keepalive_send_recv() since we get a nested response
      res = http_send_recv(port: port, data: req);
      res = bin2string(ddata: res, noprint_replacement: "");
      if (!res || (res !~ "^HTTP/1\.[01] 100" && res !~ "^HTTP/1\.[01] 200" && res !~ "^HTTP/1\.[01] 401"))
        continue;
      # <Attribute name="TradeName" type="string" xml:space="preserve">ApeosPort C3070</Attribute>
      mod = eregmatch(pattern: '"TradeName"[^>]+>(ApeosPort[^<]+)', string:res);
      if (!isnull(mod[1])) {
        concl += '\n    ' + mod[0];
        conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        model = mod[1];
      }
      vers = eregmatch(pattern: '"CurrentVersion"[^>]+>([.0-9]+)', string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concl += '\n    ' + vers[0];
      }
    } else if ('"name">DC-' >< pattern) {
      # <td align="left" valign="middle" class="name">DC-260-D44DB8</td>
      model = "DocuColor " + match[1];
    } else {
      # Product Name</td><td class=std_2>DocuCentre SC2020
      model = chomp(match[1]);
    }

    set_kb_item(name: "fujifilm/printer/detected", value: TRUE);
    set_kb_item(name: "fujifilm/printer/http/detected", value: TRUE);
    set_kb_item(name: "fujifilm/printer/http/port", value: port);
    set_kb_item(name: "fujifilm/printer/http/" + port + "/model", value: model);

    if (version == "unknown") {
      # DocuPrint
      # Version</td><td class=std_2>201210101131</td></tr>
      vers = eregmatch(pattern: "Version</td><td class=std_2>([0-9]+)<", string: buf);
      if (!isnull(vers[1])) {
        version = vers[1];
        concl += '\n    ' + vers[0];
      }
    }

    if (version == "unknown") {
      # DocuPrint older versions
      # Version</font></b></td><td width=50%><font size=-1>200708161156
      vers = eregmatch(pattern: ">Version</font></b></td><td [^>]+><font [^>]+>([0-9]+)", string: buf);
      if (!isnull(vers[1])) {
        version = vers[1];
        concl += '\n    ' + vers[0];
      }
    }

    if (version == "unknown") {
      # Apeos
      # "SoftwareVersion":"22.12.2"
      vers = eregmatch(pattern: '"SoftwareVersion"\\s*:\\s*"([.0-9]+)"', string: buf);
      if (!isnull(vers[1])) {
        version = vers[1];
        concl += '\n    ' + vers[0];
      }
    }

    set_kb_item(name: "fujifilm/printer/http/" + port + "/fw_version", value: vers[1]);
    set_kb_item(name: "fujifilm/printer/http/" + port + "/concluded", value: concl);
    set_kb_item(name: "fujifilm/printer/http/" + port + "/concludedUrl", value: conclUrl);
    exit(0);
  }
}

exit(0);
