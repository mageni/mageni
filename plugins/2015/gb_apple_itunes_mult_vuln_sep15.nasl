###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_itunes_mult_vuln_sep15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Apple iTunes Multiple Vulnerabilities Sep15 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806063");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-1157", "CVE-2015-3686", "CVE-2015-3687", "CVE-2015-3688",
                "CVE-2015-5755", "CVE-2015-5761", "CVE-2015-5874", "CVE-2014-8146",
                "CVE-2015-1205", "CVE-2010-3190", "CVE-2015-1152", "CVE-2015-1153",
                "CVE-2015-3730", "CVE-2015-3731", "CVE-2015-3733", "CVE-2015-3734",
                "CVE-2015-3735", "CVE-2015-3736", "CVE-2015-3737", "CVE-2015-3738",
                "CVE-2015-3739", "CVE-2015-3740", "CVE-2015-3741", "CVE-2015-3742",
                "CVE-2015-3743", "CVE-2015-3744", "CVE-2015-3745", "CVE-2015-3746",
                "CVE-2015-3747", "CVE-2015-3748", "CVE-2015-5823", "CVE-2015-5920",
                "CVE-2015-3749", "CVE-2015-5789", "CVE-2015-5790", "CVE-2015-5791",
                "CVE-2015-5792", "CVE-2015-5793", "CVE-2015-5794", "CVE-2015-5795",
                "CVE-2015-5796", "CVE-2015-5797", "CVE-2015-5798", "CVE-2015-5799",
                "CVE-2015-5800", "CVE-2015-5801", "CVE-2015-5802", "CVE-2015-5803",
                "CVE-2015-5804", "CVE-2015-5805", "CVE-2015-5806", "CVE-2015-5807",
                "CVE-2015-5808", "CVE-2015-5809", "CVE-2015-5810", "CVE-2015-5811",
                "CVE-2015-5812", "CVE-2015-5813", "CVE-2015-5814", "CVE-2015-5815",
                "CVE-2015-5816", "CVE-2015-5817", "CVE-2015-5818", "CVE-2015-5819",
                "CVE-2015-5821", "CVE-2015-5822");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-01 10:34:38 +0530 (Thu, 01 Oct 2015)");
  script_name("Apple iTunes Multiple Vulnerabilities Sep15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple memory corruption issues in the processing of unicode strings.

  - Multiple memory corruption issues in the processing of text files.

  - A security issue in Microsoft Foundation Class's handling of library loading.

  - Multiple memory corruption issues in WebKit.

  - A redirection issue in the handling of certain network connections.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to obtain encrypted SMB credentials, to cause unexpected application
  termination or arbitrary code execution, .");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.3 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes 12.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT201222");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/Sep/msg00003.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
  script_xref(name:"URL", value:"http://www.apple.com/itunes");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ituneVer = get_app_version(cpe:CPE)){
  exit(0);
}

##  Check for Apple iTunes vulnerable versions
if(version_is_less(version:ituneVer, test_version:"12.3"))
{
  report = 'Installed version: ' + ituneVer + '\n' +
           'Fixed version:     12.3 \n';
  security_message(data:report);
  exit(0);
}
