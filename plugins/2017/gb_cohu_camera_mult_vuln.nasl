###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cohu_camera_mult_vuln.nasl 11936 2018-10-17 09:05:37Z mmartin $
#
# Cohu 3960HD Multiple Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.140533");
  script_version("$Revision: 11936 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 11:05:37 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-24 10:59:47 +0700 (Fri, 24 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-8860", "CVE-2017-8861", "CVE-2017-8862", "CVE-2017-8863", "CVE-2017-8864");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Cohu 3960HD Multiple Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Cohu/banner");

  script_tag(name:"summary", value:"Cohu 3960HD Series IP cameras are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Cohu 3960HD Series IP cameras are prone to multiple vulnerabilities:

  - Information exposure through directory listing (CVE-2017-8860)

  - Cleartext transmission of sensitive information

  - Missing authentication for critical function (CVE-2017-8861)

  - Unrestricted upload of file with dangerous type (CVE-2017-8862)

  - Information exposure through source code (CVE-2017-8863)

  - Client side enforcement of server side security (CVE-2017-8864)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://bneg.io/2017/05/12/vulnerabilities-in-cohu-3960hd/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "//";

if (http_vuln_check(port: port, url: url, pattern: "Directory listing of", check_header: TRUE, usecache: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
