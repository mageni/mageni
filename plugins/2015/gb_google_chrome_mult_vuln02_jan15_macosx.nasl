###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities -02 Jan15 (Mac OS X)
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805422");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2015-1346", "CVE-2015-1205", "CVE-2014-7948", "CVE-2014-7947",
                "CVE-2014-7946", "CVE-2014-7945", "CVE-2014-7944", "CVE-2014-7943",
                "CVE-2014-7942", "CVE-2014-7941", "CVE-2014-7940", "CVE-2014-7939",
                "CVE-2014-7938", "CVE-2014-7937", "CVE-2014-7936", "CVE-2014-7935",
                "CVE-2014-7934", "CVE-2014-7933", "CVE-2014-7932", "CVE-2014-7931",
                "CVE-2014-7930", "CVE-2014-7929", "CVE-2014-7928", "CVE-2014-7927",
                "CVE-2014-7926", "CVE-2014-7925", "CVE-2014-7924", "CVE-2014-7923",
                "CVE-2014-9648", "CVE-2014-9647", "CVE-2014-9646", "CVE-2015-1361",
                "CVE-2015-1360", "CVE-2015-1359", "CVE-2015-1248", "CVE-2014-9654");
  script_bugtraq_id(72288);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2015-01-27 17:11:51 +0530 (Tue, 27 Jan 2015)");
  script_name("Google Chrome Multiple Vulnerabilities -02 Jan15 (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists. For more details
  about the vulnerabilities, refer the reference section.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service attack, man-in-the-middle attack, bypass
  certain security restrictions and compromise a user's system, bypass the
  SafeBrowsing or possibly have unspecified other impacts.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  40.0.2214.91 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  40.0.2214.91 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/62383");
  script_xref(name:"URL", value:"https://code.google.com/p/chromium/issues/detail?id=380663");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2015/01/stable-update.html");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
chr_ver  = infos['version'];
chrPath = infos['location'];

if(version_is_less(version:chr_ver, test_version:"40.0.2214.91"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"40.0.2214.91", install_path:chrPath);
  security_message(data:report);
  exit(0);
}
exit(0);

