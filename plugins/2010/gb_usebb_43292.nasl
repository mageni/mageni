###############################################################################
# OpenVAS Vulnerability Test
#
# UseBB Forum and Topic Feed Security Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100812");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)");
  script_bugtraq_id(43292);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("UseBB Forum and Topic Feed Security Bypass Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43292");
  script_xref(name:"URL", value:"http://www.usebb.net/community/topic.php?id=2501");
  script_xref(name:"URL", value:"http://www.usebb.net/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_usebb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("usebb/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"UseBB is prone to a security-bypass vulnerability.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to gain access to restricted
  forum and feed content.");

  script_tag(name:"affected", value:"Versions prior to UseBB 1.0.11 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(vers = get_version_from_kb(port:port, app:"UseBB")) {
  if(version_is_less_equal(version: vers, test_version: "1.0.11")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);