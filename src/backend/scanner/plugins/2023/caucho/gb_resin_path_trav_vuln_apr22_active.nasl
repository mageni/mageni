# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:caucho:resin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149808");
  script_version("2023-07-03T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-03 05:06:07 +0000 (Mon, 03 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-06-15 07:35:57 +0000 (Thu, 15 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-11 18:40:00 +0000 (Mon, 11 Apr 2022)");

  script_cve_id("CVE-2021-44138");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Caucho Resin 4.0.52 - 4.0.56 Path Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_caucho_resin_http_detect.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_mandatory_keys("caucho/resin/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Caucho Resin is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"There is a path traversal vulnerability in Caucho Resin which
  allows remote attackers to read files in arbitrary directories via a semicolon in a pathname
  within an HTTP request.");

  script_tag(name:"affected", value:"Caucho Resin version 4.0.52 through 4.0.56.");

  script_tag(name:"solution", value:"Update to a later version.");

  script_xref(name:"URL", value:"https://github.com/maybe-why-not/reponame/issues/2");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

base_pattern  = "^\s*<(web-app( .+|>$)|servlet(-mapping)?>$)";
extra_pattern = "^\s*</(web-app|servlet(-mapping)?)>$";

# nb: We need a valid web application deployed so we are iterating over all known dirs
foreach dir (make_list_unique("/", "/resin-doc", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  # Note: e.g. /;/WEB-INF/web.xml is already checked by 2021/gb_web-inf_semicolonslash_info_disclosure.nasl
  # so no need to test it twice. We're only doing a check for '/resin-web.xml' because it has been
  # determined that some targets only have 'resin-web.xml' exposed.
  url = dir + "/;/WEB-INF/resin-web.xml";

  if (http_vuln_check(port: port, url: url, pattern: base_pattern, check_header: TRUE,
                      extra_check: extra_pattern)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
