###############################################################################
# OpenVAS Vulnerability Test
#
# phpGroupWare Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100640");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-05-17 12:46:01 +0200 (Mon, 17 May 2010)");
  script_bugtraq_id(40167, 40168);
  script_cve_id("CVE-2010-0403", "CVE-2010-0404");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("phpGroupWare Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40168");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40167");
  script_xref(name:"URL", value:"http://www.phpgroupware.org/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("phpgroupware_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpGroupWare/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released phpGroupWare 0.9.16.016 to address this issue.
  Please see the references for more information.");

  script_tag(name:"summary", value:"phpGroupWare is prone to multiple SQL-injection vulnerabilities and
  to a Local File Include Vulnerability because it fails to sufficiently
  sanitize user-supplied data before using it.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to compromise the
  application, access or modify data, exploit latent vulnerabilities
  in the underlying database or to view files and execute local scripts
  in the context of the webserver process.");

  script_tag(name:"affected", value:"Versions of phpGroupWare prior to 0.9.16.016 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(vers = get_version_from_kb(port:port,app:"phpGroupWare")) {
  if(version_is_less(version: vers, test_version: "0.9.16.016")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);