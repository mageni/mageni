###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perforce_multiple_versions.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Perforce Multiple Vulnerabilities
#
# Authors:
# Michael Meyer
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
  script_oid("1.3.6.1.4.1.25623.1.0.100521");
  script_version("$Revision: 14326 $");
  script_cve_id("CVE-2010-0934");
  script_bugtraq_id(38589, 38595);
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-09 14:33:24 +0100 (Tue, 09 Mar 2010)");
  script_name("Perforce Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38589");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38595");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56738");
  script_xref(name:"URL", value:"http://www.perforce.com/perforce/products/p4web.html");
  script_xref(name:"URL", value:"http://resources.mcafee.com/forms/Aurora_VDTRG_WP");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("perforce_detect.nasl");
  script_require_ports("Services/perforce", 1666);
  script_tag(name:"summary", value:"Perforce Server is prone to Multiple Vulnerabilities.

1. A security-bypass vulnerability.
Attackers may exploit the issue to bypass certain security
restrictions and perform unauthorized actions.

2. A session-hijacking vulnerability.
An attacker can exploit this issue to gain access to the affected
application.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/perforce");
if(!port)exit(0);
if (!get_tcp_port_state(port))exit(0);

if(!vers = get_kb_item(string("perforce/", port, "/version")))exit(0);
if(!isnull(vers)) {

  if(!version = split(vers, sep: "/", keep: 0))exit(0);
  if(version_is_equal(version: version[2], test_version: "2009.2") ||
     version_is_equal(version: version[2], test_version: "2007.2") ||
     version_is_equal(version: version[2], test_version: "2007.1") ||
     version_is_equal(version: version[2], test_version: "2006.2") ||
     version_is_equal(version: version[2], test_version: "2006.1")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
