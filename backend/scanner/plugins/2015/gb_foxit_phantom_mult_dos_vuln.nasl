###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_phantom_mult_dos_vuln.nasl 2015-05-05 10:41:19 +0530 May$
#
# Foxit PhantomPDF Multiple Denial of Service Vulnerabilities
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805378");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-3633", "CVE-2015-3632");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-05 10:41:19 +0530 (Tue, 05 May 2015)");
  script_name("Foxit PhantomPDF Multiple Denial of Service Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Foxit PhantomPDF
  and is prone to Multiple Denial of Service Vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to
  user-supplied input is not properly validated

  - when handling invalid streams and

  - when performing digital signature verification.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause multiple denial-of-service attacks.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version 7.1.0.306,
  7.1.2.311 and 7.1.3.320.");

  script_tag(name:"solution", value:"Upgrade to Foxit PhantomPDF version
  7.1.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.foxitsoftware.com/support/security_bulletins.php#FRD-27");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!foxitVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:foxitVer, test_version:"7.1.0.306") ||
   version_is_equal(version:foxitVer, test_version:"7.1.2.311") ||
   version_is_equal(version:foxitVer, test_version:"7.1.3.320"))
{
  report = 'Installed version: ' + foxitVer + '\n' +
           'Fixed version:     7.1.5'  + '\n';
  security_message(data:report);
  exit(0);
}

exit(99);