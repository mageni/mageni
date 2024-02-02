# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100752");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-08-10 14:55:08 +0200 (Tue, 10 Aug 2010)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Nagios XI Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Nagios XI.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.nagios.com/products/nagios-xi/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/nagiosxi", "/nagios", http_cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  url1 = dir + "/login.php";
  buf1 = http_get_cache(item:url1, port:port);

  url2 = dir + "/about/";
  buf2 = http_get_cache(item:url2, port:port);

  if(!buf1 && !buf2)
    continue;

  found = FALSE;

  if(
      (egrep(pattern:"^Set-Cookie\s*:\s*nagiosxi", string:buf1, icase:TRUE) &&
        ("Nagios Enterprises" >< buf1 ||
         "Produced by Nagios XI" >< buf1) &&
        (# <title>Nagios XI - Login</title>
         "Nagios XI - Login" >< buf1 ||
         # <h2>Nagios XI</h2>
         # <a href="http://nagios.com/products/nagiosxi" target="new"><strong>Nagios XI</strong></a>                                             </div>
         ">Nagios XI<" >< buf1 ||
         # <title>Login &middot; Nagios XI</title>
         "<title>Login &middot; Nagios XI</title>" >< buf1)) ||
      '<input type="hidden" name="product" value="nagiosxi">' >< buf1
    ) {

    found = TRUE;
    conclUrl = "  " + http_report_vuln_url(port:port, url:url1, url_only:TRUE);
  }

  # nb: Not always there (some systems are showing a 404)...
  # e.g.:
  # <a  href="main.php?=about" target="maincontentframe">About Nagios XI</a>
  # <a href="http://nagios.com/products/nagiosxi" target="new"><b>Nagios XI</b></a>                                             </div>
  # <a href="http://nagios.com/products/nagiosxi" target="new"><strong>Nagios XI</strong></a>                                             </div>
  if(">About Nagios XI</a>" >< buf2 ||
     egrep(string:buf2, pattern:"https?://nagios\.com/products/nagiosxi[^/]+<(b|strong)>Nagios XI</(b|strong)>", icase:FALSE)
    ) {

    found = TRUE;
    if(conclUrl)
      conclUrl += '\n';
    conclUrl += "  " + http_report_vuln_url(port:port, url:url2, url_only:TRUE);
  }

  if(found) {

    version = "unknown";

    if(buf1) {
      # <div id="footernotice">Nagios XI 2012R2.9  Copyright &copy; 2008-2023 <a href="http://www.nagios.com/" target="_blank">Nagios Enterprises, LLC</a>.</div>
      # <div id="footernotice">Nagios XI 2012R1.6  Copyright &copy; 2008-2023 <a href="http://www.nagios.com/" target="_blank">Nagios Enterprises, LLC</a>.</div>
      # <div id="footernotice">Nagios XI 2011R3.3  Copyright &copy; 2008-2023 <a href="http://www.nagios.com/" target="_blank">Nagios Enterprises, LLC</a>.</div>
      # <div id="footernotice">Nagios XI 2011R1.8  Copyright &copy; 2008-2011 <a href="http://www.nagios.com/" target="_blank">Nagios Enterprises, LLC</a>.</div>
      # nb: These also had the 'name="version"' string from above included as well while the
      # 2014R2.7 and later seems to miss these now.
      vers = eregmatch(string:buf1, pattern:'footernotice">Nagios XI (20[0-9]{2}[^ ]+)', icase:TRUE);
      if(!isnull(vers[1])) {
        version = chomp(vers[1]);
      } else {
        # <input type="hidden" name="version" value="5.4.7">
        # <input type="hidden" name="build" value="1499702040">
        #
        # <input type="hidden" name="version" value="5.4.13">
        # <input type="hidden" name="build" value="1520960080">
        #
        # <input type="hidden" name="version" value="5.4.0">
        # <input type="hidden" name="build" value="1482952071">
        #
        # <input type="hidden" name="version" value="5.4.11">
        # <input type="hidden" name="build" value="1509572737">
        #
        # <input type="hidden" name="version" value="2012R2.9">
        # <input type="hidden" name="build" value="20140211">
        #
        # <input type="hidden" name="version" value="2012R1.6">
        # <input type="hidden" name="build" value="20130205">
        #
        # <input type="hidden" name="version" value="2014R2.7">
        # <input type="hidden" name="build" value="20150423">
        #
        # <input type="hidden" name="version" value="2011R3.3">
        # <input type="hidden" name="build" value="20120820">
        #
        # <input type="hidden" name="version" value="2011R1.8">
        # <input type="hidden" name="build" value="20111028">
        vers = eregmatch(string:buf1, pattern:'name="version" value="([0-9.]+|20[0-9]{2}[^ ]+)">');
        if(!isnull(vers[1]))
          version = chomp(vers[1]);
      }
    }

    set_kb_item(name:"nagios/nagios_xi/detected", value:TRUE);
    set_kb_item(name:"nagios/nagios_xi/http/detected", value:TRUE);

    cpe = build_cpe(value:version, exp:"([0-9.]+|20[0-9]{2}[^ ]+)", base:"cpe:/a:nagios:nagios_xi:");
    if(!cpe)
      cpe = "cpe:/a:nagios:nagios_xi";

    # nb: CPEs should be always lowercase and as the version could be e.g. 2011R1.8 we're converting
    # it to lowercase here.
    cpe = tolower(cpe);

    # nb: Seems to only run on Linux according to:
    # https://assets.nagios.com/downloads/nagiosxi/guides/administrator/installation.php
    os_register_and_report(os:"Linux", cpe:"cpe:/o:linux:kernel", desc:"Nagios XI Detection (HTTP)", runs_key:"unixoide");

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Nagios XI", version:version, install:install,
                                            cpe:cpe, concluded:vers[0], concludedUrl:conclUrl),
                port:port);

    exit(0);
  }
}

exit(0);
