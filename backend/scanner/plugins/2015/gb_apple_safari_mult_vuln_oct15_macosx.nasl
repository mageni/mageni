###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln_oct15_macosx.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# Apple Safari Multiple Vulnerabilities-01 Oct15 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805989");
  script_version("$Revision: 12391 $");
  script_cve_id("CVE-2015-5764", "CVE-2015-5765", "CVE-2015-5767", "CVE-2015-5780",
                "CVE-2015-5788", "CVE-2015-5789", "CVE-2015-5790", "CVE-2015-5791",
                "CVE-2015-5792", "CVE-2015-5793", "CVE-2015-5794", "CVE-2015-5795",
                "CVE-2015-5796", "CVE-2015-5797", "CVE-2015-5798", "CVE-2015-5799",
                "CVE-2015-5800", "CVE-2015-5801", "CVE-2015-5802", "CVE-2015-5803",
                "CVE-2015-5804", "CVE-2015-5805", "CVE-2015-5806", "CVE-2015-5807",
                "CVE-2015-5808", "CVE-2015-5809", "CVE-2015-5810", "CVE-2015-5811",
                "CVE-2015-5812", "CVE-2015-5813", "CVE-2015-5814", "CVE-2015-5815",
                "CVE-2015-5816", "CVE-2015-5817", "CVE-2015-5818", "CVE-2015-5819",
                "CVE-2015-5821", "CVE-2015-5822", "CVE-2015-5823", "CVE-2015-3801",
                "CVE-2015-5825", "CVE-2015-5820", "CVE-2015-5826", "CVE-2015-5827",
                "CVE-2015-5828");
  script_bugtraq_id(76764, 76766, 76763, 76765);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-13 13:40:06 +0530 (Tue, 13 Oct 2015)");
  script_name("Apple Safari Multiple Vulnerabilities-01 Oct15 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Apple Safari
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists as,

  - Multiple user interface inconsistencies exists which can allow a malicious
    website to display an arbitrary URL.

  - A validated, user-installed Safari extension could be replaced on disk
    without prompting the user.

  - A race condition existed in validation of image origins.

  - Multiple memory corruption issues existed in WebKit.

  - WebKit would accept multiple cookies to be set in the 'document.cookie' API.

  - WebKit's Performance API could have allowed a malicious website to leak
    browsing history, network activity, and mouse movements by measuring time.

  - An issue existed in handling of tel://, facetime://, and facetime-audio:// URLs.

  - Safari allowed cross-origin stylesheets to be loaded with non-CSS MIME types
    which could be used for cross-origin data exfiltration.

  - An object leak issue broke the isolation boundary between origins.

  - The Safari plugins API did not communicate to plugins that a server-side
    redirect had happened.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct spoofing attacks, replace genuine extensions, bypass security
  restrictions, conduct denial-of-service attack, arbitrary code execution, gain
  access to sensitive information or url redirection.");

  script_tag(name:"affected", value:"Apple Safari versions before 9.0");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 9.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205265");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/Sep/msg00007.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.apple.com/support");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!safVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:safVer, test_version:"9.0"))
{
  report = 'Installed version: ' + safVer + '\n' +
           'Fixed version:     ' + "9.0" + '\n';
  security_message(data:report);
  exit(0);
}
