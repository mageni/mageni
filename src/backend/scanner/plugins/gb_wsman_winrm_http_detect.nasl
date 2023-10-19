# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103923");
  script_version("2023-10-11T05:05:54+0000");
  script_tag(name:"last_modification", value:"2023-10-11 05:05:54 +0000 (Wed, 11 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-03-19 12:39:47 +0100 (Wed, 19 Mar 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Web Services Management (WS-Man) / Windows Remote Management (WinRM) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 5985);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Web Services Management (WS-Man) /
  Windows Remote Management (WinRM).");

  script_xref(name:"URL", value:"https://www.dmtf.org/standards/ws-man");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/windows/win32/winrm/portal");

  exit(0);
}

include("byte_func.inc");
include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 5985);

banner = http_get_remote_headers(port: port);

if (!banner || banner !~ "HTTP/(2|1\.[01]) (404|405|501)")
  exit(0);

headers = make_array("Content-Type", "application/soap+xml;charset=UTF-8",
                     "WSMANIDENTIFY", "unauthenticated");

data = '<?xml version="1.0" encoding="UTF-8"?>\n' +
       '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
       'xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">' +
       '<s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>';

foreach url (make_list("/wsman-anon", "/wsman")) {
  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req, fetch404: TRUE);

  if (res =~ 'Basic\\s*realm="OPENWSMAN"' || "<wsmid:IdentifyResponse" >< res) {
    set_kb_item(name: "wsman/detected", value: TRUE);
    set_kb_item(name: "wsman/http/detected", value: TRUE);

    service_register(port: port, proto: "wsman");

    report = "A WS-Man service is running at this port.";

    if ("<wsmid:IdentifyResponse" >< res) {
      set_kb_item(name: "winrm/detected", value: TRUE);
      set_kb_item(name: "winrm/http/detected", value: TRUE);
      service_register(port: port, proto: "winrm");

      report += '\n\nThe service supports Windows Remote Management (WinRM).';

      # <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header/><s:Body><wsmid:IdentifyResponse xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion><wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor><wsmid:ProductVersion>OS: 0.0.0 SP: 0.0 Stack: 3.0</wsmid:ProductVersion></wsmid:IdentifyResponse></s:Body></s:Envelope>
      vend = eregmatch(pattern: "<wsmid:ProductVendor>([^<]+)", string: res);
      if (!isnull(vend[1]))
        vendor = vend[1];

      vers = eregmatch(pattern: "<wsmid:ProductVersion>([^<]+)", string: res);
      if (!isnull(vers[1]))
        version = vers[1];

      if (vendor || version) {
        report += '\n\nThe following information was extracted:\n';
        if (vendor)
          report += "  Product Vendor: " + vendor + '\n';
        if (version)
          report += "  Product Version: " + version + '\n';
      }

      headers = make_array("Authorization", "Negotiate TlRMTVNTUAABAAAAt4II4gAAAAAAAAAAAAAAAAAAAAAGAHIXAAAADw==",
                           "Content-Type", "application/soap+xml;charset=UTF-8",
                           "Content-Length", 0); # nb: Content-Length is needed
      data = "";

      req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      ntlm = eregmatch(pattern: 'Negotiate (TlRMTVNT[^\n\r]+)', string: res, icase: FALSE);
      if (!isnull(ntlm[1]) && strlen(ntlm[1]) >= 52) {
        ntlm = base64_decode(str: ntlm[1]);
        version_bytes = substr(ntlm, 48, 52);
        os_version = ord(version_bytes[0]) + "." + ord(version_bytes[1]) + "." +
                       getword(blob: version_bytes, pos: 2);

        report += '\nThe following information was extracted from the NTLM challenge:\n';
        report += "  OS Version: " + os_version;
      }

      os_cpe = build_cpe(value: os_version, exp: "^([0-9.]+)", base: "cpe:/o:microsoft:windows:");
      if (!os_cpe)
        os_cpe = "cpe:/o:microsoft:windows";

      os_register_and_report(os: "Microsoft Windows", cpe: os_cpe, port: port, runs_key: "windows",
                             desc: "Web Services Management (WS-Man) / Windows Remote Management (WinRM) Detection (HTTP)");
    }

    report += '\n\nConcluded from version/product identification location: ' +
              http_report_vuln_url(port: port, url: url, url_only: TRUE);

    log_message(port: port, data: chomp(report));
    exit(0);
  }
}

exit(0);
