###############################################################################
# OpenVAS Vulnerability Test
# $Id: ntop_36074.nasl 13957 2019-03-01 09:46:54Z ckuersteiner $
#
# ntop HTTP Basic Authentication NULL Pointer Dereference Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:ntop:ntop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100255");
  script_version("$Revision: 13957 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 10:46:54 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-08-23 12:14:46 +0200 (Sun, 23 Aug 2009)");
  script_bugtraq_id(36074);
  script_cve_id("CVE-2009-2732");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("ntop HTTP Basic Authentication NULL Pointer Dereference Denial Of Service Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ntop_detect.nasl");
  script_mandatory_keys("ntop/installed");
  script_require_ports("Services/www", 3000);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36074");
  script_xref(name:"URL", value:"http://www.ntop.org/ntop.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/505876");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/505862");

  script_tag(name:"summary", value:"The 'ntop' tool is prone to a denial-of-service vulnerability because
  of a NULL-pointer dereference that occurs when crafted HTTP Basic Authentication credentials are
  received by the embedded webserver.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the affected application,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"This issue affects ntop 3.3.10, other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:version, test_version:"3.3.10" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit( 0 );
}

exit( 99 );
