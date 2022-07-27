###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_squid_dos_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Squid External Auth Header Parser DOS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101105");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-08-24 07:49:31 +0200 (Mon, 24 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2855");
  script_name("Squid External Auth Header Parser DOS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl");
  script_require_ports("Services/http_proxy", 3128, "Services/www", 8080);
  script_mandatory_keys("squid_proxy_server/installed");

  script_xref(name:"URL", value:"http://www.squid-cache.org/bugs/show_bug.cgi?id=2704");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/08/03/3");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=534982");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of service
  via a crafted auth header with certain comma delimiters that trigger an infinite
  loop of calls to the strcspn function.");

  script_tag(name:"affected", value:"Squid Version 2.7.X");

  script_tag(name:"insight", value:"The flaw is due to error in 'strListGetItem()' function within
  'src/HttpHeaderTools.c'.");

  script_tag(name:"solution", value:"Upgrade to Squid Version 3.1.4 or later.");

  script_tag(name:"summary", value:"This host is running Squid and is  prone to Denial Of
  Service vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers =~ "^2\.7" ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.1.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );