##############################################################################
# OpenVAS Vulnerability Test
#
# Novell eDirectory NCP Request Remote Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902291");
  script_version("2019-05-10T14:24:23+0000");
  script_cve_id("CVE-2010-4327");
  script_bugtraq_id(46263);
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Novell eDirectory NCP Request Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("novell_edirectory_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("eDirectory/installed", "Host/runs_unixoide"); # only eDirectory running under Linux is affected

  script_xref(name:"URL", value:"http://secunia.com/advisories/43186");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0305");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-060/");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=7007781&sliceId=2");

  script_tag(name:"insight", value:"This flaw is caused by an error in the 'NCP' implementation when processing
  malformed 'FileSetLock' requests sent to port 524.");
  script_tag(name:"solution", value:"Upgrade to Novell eDirectory  8.8.5.6 or  8.8.6.2");
  script_tag(name:"summary", value:"This host is running Novell eDirectory is prone to denial of
  service vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a vulnerable
  service to become unresponsive, leading to a denial of service condition.");
  script_tag(name:"affected", value:"Novell eDirectory 8.8.5 before 8.8.5.6 (8.8.5.SP6)
  Novell eDirectory 8.8.6 before 8.8.6.2 (8.8.6.SP2) on Linux.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.novell.com/products/edirectory/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = make_list( "cpe:/a:novell:edirectory","cpe:/a:netiq:edirectory" );

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! major = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( ! sp = get_kb_item( "ldap/eDirectory/" + port + "/sp" ) )
  sp = "0";

instvers = major;

if( sp > 0 )
  instvers += ' SP' + sp;

edirVer = major + '.' + sp;

if(version_in_range(version:edirVer, test_version:"8.8.5", test_version2:"8.8.5.5") ||
   version_in_range(version:edirVer, test_version:"8.8.6", test_version2:"8.8.6.1")) {
  report =  report_fixed_ver( installed_version:instvers, fixed_version:"See advisory" );
  security_message( port:port, data:report );
  exit( 0 );
}


exit( 99 );
