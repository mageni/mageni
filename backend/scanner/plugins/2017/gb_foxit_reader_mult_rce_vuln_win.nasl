###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_mult_rce_vuln_win.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Foxit Reader Multiple Remote Code Execution Vulnerabilities (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811585");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-10952", "CVE-2017-10951");
  script_bugtraq_id(100412, 100409);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-21 13:07:23 +0530 (Mon, 21 Aug 2017)");
  script_name("Foxit Reader Multiple Remote Code Execution Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with Foxit Reader
  and is prone to multiple remote code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The lack of proper validation of user-supplied data in the 'saveAs JavaScript'
    function, which can lead to writing arbitrary files into attacker controlled
    locations.

  - The lack of proper validation of a user-supplied string before using it to
    execute a system call in app.launchURL method.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute code under the context of the current process.");

  script_tag(name:"affected", value:"All Foxit Reader versions on windows
  with 'Safe reading mode' feature disabled.");

  script_tag(name:"solution", value:"Mitigation is available,
  Safe reading mode should be enabled always and additionally users can also
  uncheck the 'Enable JavaScript Actions' from Foxit's Preferences menu,
  although this may break some functionality.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod", value:"30");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-691");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-692");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/blog/2017/8/17/busting-myths-in-foxit-reader");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## All foxit reader installations are detected as vulnerable independent of version
## Because Foxit refused to patch both the vulnerabilities because they would not work with the
## "safe reading mode" feature that fortunately comes enabled by default in Foxit Reader.
if(foxitVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"Mitigation");
  security_message(data:report);
  exit(0);
}
