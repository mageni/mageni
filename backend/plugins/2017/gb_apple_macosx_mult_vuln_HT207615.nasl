###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln_HT207615.nasl 14295 2019-03-18 20:16:46Z cfischer $
#
# Apple Mac OS X Multiple Vulnerabilities-HT207615
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810728");
  script_version("$Revision: 14295 $");
  script_cve_id("CVE-2016-0736", "CVE-2016-2161", "CVE-2016-5387", "CVE-2016-8740",
                "CVE-2016-8743", "CVE-2016-10158", "CVE-2016-10159", "CVE-2016-10160",
                "CVE-2016-10161", "CVE-2016-9935", "CVE-2017-2421", "CVE-2017-2438",
                "CVE-2017-2430", "CVE-2017-2462", "CVE-2017-2420", "CVE-2017-2427",
                "CVE-2017-2449", "CVE-2017-2379", "CVE-2017-2417", "CVE-2017-2431",
                "CVE-2017-2435", "CVE-2017-2450", "CVE-2017-2461", "CVE-2016-9586",
                "CVE-2016-7585", "CVE-2017-2429", "CVE-2017-2487", "CVE-2017-2406",
                "CVE-2017-2407", "CVE-2017-2439", "CVE-2017-2428", "CVE-2017-2418",
                "CVE-2017-2426", "CVE-2017-2416", "CVE-2017-2467", "CVE-2017-2489",
                "CVE-2016-3619", "CVE-2017-2443", "CVE-2017-2408", "CVE-2017-2436",
                "CVE-2017-2437", "CVE-2017-2388", "CVE-2017-2398", "CVE-2017-2401",
                "CVE-2017-2410", "CVE-2017-2440", "CVE-2017-2456", "CVE-2017-2472",
                "CVE-2017-2473", "CVE-2017-2474", "CVE-2017-2478", "CVE-2017-2482",
                "CVE-2017-2483", "CVE-2017-2458", "CVE-2017-2448", "CVE-2017-2390",
                "CVE-2017-2441", "CVE-2017-2402", "CVE-2017-2392", "CVE-2017-2457",
                "CVE-2017-2409", "CVE-2017-2422", "CVE-2016-10009", "CVE-2016-10010",
                "CVE-2016-10011", "CVE-2016-10012", "CVE-2016-7056", "CVE-2017-2403",
                "CVE-2016-5636", "CVE-2017-2413", "CVE-2017-2423", "CVE-2017-2451",
                "CVE-2017-2485", "CVE-2017-2425", "CVE-2017-2381", "CVE-2017-6974",
                "CVE-2016-7922", "CVE-2016-7923", "CVE-2016-7924", "CVE-2016-7925",
                "CVE-2016-7926", "CVE-2016-7927", "CVE-2016-7928", "CVE-2016-7929",
                "CVE-2016-7930", "CVE-2016-7931", "CVE-2016-7932", "CVE-2016-7933",
                "CVE-2016-7934", "CVE-2016-7935", "CVE-2016-7936", "CVE-2016-7937",
                "CVE-2016-7938", "CVE-2016-7939", "CVE-2016-7940", "CVE-2016-7973",
                "CVE-2016-7974", "CVE-2016-7975", "CVE-2016-7983", "CVE-2016-7984",
                "CVE-2016-7985", "CVE-2016-7986", "CVE-2016-7992", "CVE-2016-7993",
                "CVE-2016-8574", "CVE-2016-8575", "CVE-2017-5202", "CVE-2017-5203",
                "CVE-2017-5204", "CVE-2017-5205", "CVE-2017-5341", "CVE-2017-5342",
                "CVE-2017-5482", "CVE-2017-5483", "CVE-2017-5484", "CVE-2017-5485",
                "CVE-2017-5486", "CVE-2016-3619", "CVE-2016-9533", "CVE-2016-9535",
                "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9538", "CVE-2016-9539",
                "CVE-2016-9540", "CVE-2017-2486");
  script_bugtraq_id(95078, 95076, 91816, 94650, 95077, 95764, 95774, 95783, 95768,
                    94846, 97140, 97137, 95019, 97146, 85919, 97147, 97134, 95375,
                    96767, 94968, 94972, 94977, 94975, 91247, 97132, 95852, 94742,
                    94744, 94745, 94746, 94753, 94754, 94747, 97300, 97303);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 21:16:46 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-03-31 17:37:14 +0530 (Fri, 31 Mar 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-HT207615");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists. For details
  refer the reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption),
  gain access to potentially sensitive information, bypass certain protection
  mechanism and have other impacts.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.12.x through
  10.12.3");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.12.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207615");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.12");
  script_xref(name:"URL", value:"https://www.apple.com");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
  exit(0);
}

if("Mac OS X" >< osName)
{
  if(version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.3"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.12.4");
    security_message(data:report);
    exit(0);
  }
  exit(99);
}

exit(0);