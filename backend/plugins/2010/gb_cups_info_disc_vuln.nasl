###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_info_disc_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# CUPS Information Disclosure Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801664");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-12-21 15:42:46 +0100 (Tue, 21 Dec 2010)");
  script_cve_id("CVE-2010-1748");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("CUPS Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://cups.org/str.php?L3577");
  script_xref(name:"URL", value:"http://cups.org/articles.php?L596");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40220");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_cups_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("CUPS/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive
  information from cupsd process memory via a crafted request.");
  script_tag(name:"affected", value:"CUPS version 1.4.3 and prior.");
  script_tag(name:"insight", value:"This flaw is due to an error in 'cgi_initialize_string' function in
  'cgi-bin/var.c' which mishandles input parameters containing the '%' character.");
  script_tag(name:"solution", value:"Upgrade to CUPS version 1.4.4 or later.");
  script_tag(name:"summary", value:"The host is running CUPS and is prone to Information disclosure
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.cups.org/software.php");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

url = "/admin?OP=redirect&URL=%";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( egrep( pattern:'^Location:.*%FF.*/cups/cgi-bin/admin.cgi', string:res ) ) {
  report = report_vuln_url( url:url, port:port );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );