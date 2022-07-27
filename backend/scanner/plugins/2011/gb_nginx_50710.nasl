###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_50710.nasl 13859 2019-02-26 05:27:33Z ckuersteiner $
#
# nginx DNS Resolver Remote Heap Buffer Overflow Vulnerability
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

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103344");
  script_bugtraq_id(50710);
  script_cve_id("CVE-2011-4315");
  script_version("$Revision: 13859 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("nginx DNS Resolver Remote Heap Buffer Overflow Vulnerability");

  script_tag(name:"last_modification", value:"$Date: 2019-02-26 06:27:33 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-11-21 11:12:32 +0100 (Mon, 21 Nov 2011)");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("nginx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nginx/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50710");
  script_xref(name:"URL", value:"http://nginx.org/");
  script_xref(name:"URL", value:"http://www.nginx.org/en/CHANGES");
  script_xref(name:"URL", value:"http://trac.nginx.org/nginx/changeset/4268/nginx");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");
  script_tag(name:"summary", value:"nginx is prone to a remote heap-based buffer-overflow vulnerability.");
  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute
  arbitrary code in the context of the vulnerable application. Failed
  exploit attempts will result in a denial-of-service condition.");
  script_tag(name:"affected", value:"Versions prior to nginx 1.0.10 are vulnerable.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( ! ver = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:ver, test_version:"1.0.10" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"1.0.10" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
