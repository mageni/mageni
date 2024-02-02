# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814217");
  script_version("2023-12-21T05:06:40+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-21 05:06:40 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-09-19 14:33:52 +0530 (Wed, 19 Sep 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell Printer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  # nb: Don't use e.g. webmirror.nasl or DDI_Directory_Scanner.nasl as this VT should
  # run as early as possible so that the printer can be early marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Dell printer devices.");

  exit(0);
}

include("dell_printers.inc");
include("dump.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

urls = get_dell_detect_urls();

foreach url (keys(urls)) {
  version = "unknown";

  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");

  res = http_get_cache(port: port, item: url);
  if (!res || (res !~ "^HTTP/1\.[01] 200" && res !~ "^HTTP/1\.[01] 401"))
    continue;

  # Replace non-printable characters to avoid language based false-negatives
  res = bin2string(ddata: res, noprint_replacement: "");

  if (match = eregmatch(pattern: pattern, string: res, icase: TRUE)) {
    if (isnull(match[1]))
      continue;

    concl = "    " + match[0];
    conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    model = chomp(match[1]);

    set_kb_item(name: "dell/printer/detected", value: TRUE);
    set_kb_item(name: "dell/printer/http/detected", value: TRUE);
    set_kb_item(name: "dell/printer/http/port", value: port);
    set_kb_item(name: "dell/printer/http/" + port + "/model", value: model);

    # Main&#32;Firmware&#32;Version</dt><dd>F1601111029</dd>
    vers = eregmatch(pattern: "Main[^;]+;Firmware[^;]+;Version</dt><dd>([^<]+)<", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concl += '\n    ' + vers[0];
    }

    if (version == "unknown") {
      url = "/cgi-bin/dynamic/printer/config/reports/deviceinfo.html";
      res = http_get_cache(port: port, item: url);
      # >Base</p></td><td><p> =  LW40.PRL.P439-0 </p></td>
      vers = eregmatch(pattern: ">Base</p></td><td><p>\s*=\s*([^< ]+)", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concl += '\n    ' + vers[0];
        conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    if (version == "unknown") {
      url = "/status/infomation.htm";
      res = http_get_cache(port: port, item: url);
      # >Firmware Version</td><td class=std_2>201510190654</td>
      vers = eregmatch(pattern: ">Firmware Version</td><[^>]+>([0-9]+)<", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concl += '\n    ' + vers[0];
        conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    if (version == "unknown") {
      url = "/ews/status/infomation.htm";
      res = http_get_cache(port: port, item: url);
      # Firmware Version</font></b></td><td width=50%><font size=-1>200809190845<
      vers = eregmatch(pattern: "Firmware Version</font></b></td>[^>]+>[^>]+>([0-9]+)<", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concl += '\n    ' + vers[0];
        conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    if (version == "unknown") {
      url = "/Information/firmware_version.htm";
      res = http_get_cache(port: port, item: url);
      # Main Firmware Version&nbsp;: </td> <td class="valueFont"> 2.70.00.91    10-11-2012
      vers = eregmatch(pattern: "Main Firmware Version[^>]+>[^>]+>\s*([0-9.]+)", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concl += '\n    ' + vers[0];
        conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    if (version == "unknown") {
      url = "/printer/info";
      res = http_get_cache(port: port, item: url);
      # Basic Kernel</b></td><td width="260"><code>EBR.KA.K007-0</code>
      # Basic Kernel</b></td><td width="260">E_YD.014-0</td>
      vers = eregmatch(pattern: "Basic Kernel</b></td>[^>]+>(<code>)?([^<]+)<", string: res);
      if (!isnull(vers[2])) {
        version = vers[2];
        concl += '\n    ' + vers[0];
        conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    if (version == "unknown") {
      url = "/printer_info.htm";
      res = http_get_cache(port: port, item: url);
      vers = eregmatch(pattern: ">Printer Firmware Version.*>([0-9.]+)<.*Engine Firmware Version", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concl += '\n    ' + vers[0];
        conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    set_kb_item(name: "dell/printer/http/" + port + "/version", value: version);
    set_kb_item(name: "dell/printer/http/" + port + "/concluded", value: concl);
    set_kb_item(name: "dell/printer/http/" + port + "/concludedUrl", value: conclUrl);

    exit(0);
  }
}

exit(0);
