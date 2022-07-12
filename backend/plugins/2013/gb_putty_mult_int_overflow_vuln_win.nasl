###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_putty_mult_int_overflow_vuln_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# PuTTY Multiple Integer Overflow Vulnerabilities (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:putty:putty";


if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803871");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-4206", "CVE-2013-4207", "CVE-2013-4208", "CVE-2013-4852");
  script_bugtraq_id(61645, 61649, 61644, 61599);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-21 11:16:36 +0530 (Wed, 21 Aug 2013)");
  script_name("PuTTY Multiple Integer Overflow Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with PuTTY and is prone to multiple integer overflow
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 0.63 or later.");
  script_tag(name:"insight", value:"Multiple Integer overflow errors due to,

  - Improper processing of public-key signatures.

  - Improper validation of DSA signatures in the 'modmul()' function
  (putty/sshbn.c)

  - Not removing sensitive data stored in the memory after it is no longer
  needed.

  - Input is not properly validated when handling negative SSH handshake
  message lengths in the getstring() function in sshrsa.c and sshdss.c.");
  script_tag(name:"affected", value:"PuTTY version before 0.63 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause heap-based buffer overflows,
		  resulting in a denial of service or potentially allowing the execution of arbitrary code.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54354");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q3/289");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q3/291");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-modmul.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_putty_portable_detect.nasl");
  script_mandatory_keys("putty/version");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

puttyVer = get_app_version(cpe:CPE);
if(!puttyVer){
  exit(0);
}

if(version_is_less(version:puttyVer, test_version:"0.63"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
