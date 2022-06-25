###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_subversion_binary_delta_parssing_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Subversion Binary Delta Processing Multiple Integer Overflow Vulnerabilities
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

CPE = 'cpe:/a:subversion:subversion';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101104");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2411");
  script_bugtraq_id(35983);
  script_name("Subversion Binary Delta Processing Multiple Integer Overflow Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_subversion_detect.nasl");
  script_mandatory_keys("Subversion/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36184/");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Aug/1022697.html");
  script_xref(name:"URL", value:"http://subversion.tigris.org/security/CVE-2009-2411-advisory.txt");
  script_xref(name:"URL", value:"http://subversion.tigris.org/project_packages.html");

  script_tag(name:"impact", value:"Attackers can exploit these issues to compromise an application using the library
  or crash the application, resulting into a denial of service conditions.");

  script_tag(name:"affected", value:"Subversion version 1.5.6 and prior,
  Subversion version 1.6.0 through 1.6.3.");

  script_tag(name:"insight", value:"The flaws are due to input validation errors in the processing of svndiff
  streams in the 'libsvn_delta' library.");

  script_tag(name:"solution", value:"Apply the patch from the linked references or upgrade to Subversion version 1.5.7 or 1.6.4.");

  script_tag(name:"summary", value:"The host is installed with Subversion and is prone to
  multiple Integer Overflow Vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:ver, test_version:"1.5.7")||
   version_in_range(version:ver, test_version:"1.6",test_version2:"1.6.3")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"1.5.7/1.6.4");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);