###############################################################################
# OpenVAS Vulnerability Test
#
# Novell eDirectory Multiple Vulnerabilities - Jul09 (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:novell:edirectory";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900599");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0192", "CVE-2009-2456", "CVE-2009-2457");
  script_bugtraq_id(35666);
  script_name("Novell eDirectory Multiple Vulnerabilities - Jul09 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34160");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1883");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=3426981");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/eDir/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to crash the service
  leading to denial of service condition.");

  script_tag(name:"affected", value:"Novell eDirectory 8.8 before SP5 on Windows.");

  script_tag(name:"insight", value:"- An unspecified error occurs in DS\NDSD component while processing malformed
  LDAP request containing multiple . (dot) wildcard characters in the Relative Distinguished Name (RDN).

  - An unspecified error occurs in DS\NDSD component while processing malformed
  bind LDAP packets.

  - Off-by-one error occurs in the iMonitor component while processing
  malicious HTTP request with a crafted Accept-Language header.");

  script_tag(name:"solution", value:"Upgrade to  Novell eDirectory 8.8 SP5 or later.");

  script_tag(name:"summary", value:"This host is running Novell eDirectory and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_in_range( version:vers, test_version:"8.8", test_version2:"8.8.SP4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.8 SP5", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );