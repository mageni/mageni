###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln_oct12_macosx.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Apple Safari Multiple Vulnerabilities - Oct 2012 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803032");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-3713", "CVE-2012-3714", "CVE-2012-3715", "CVE-2011-3105",
                "CVE-2012-2817", "CVE-2012-2818", "CVE-2012-2829", "CVE-2012-2831",
                "CVE-2012-2842", "CVE-2012-2843", "CVE-2012-3598", "CVE-2012-3601",
                "CVE-2012-3602", "CVE-2012-3606", "CVE-2012-3607", "CVE-2012-3612",
                "CVE-2012-3613", "CVE-2012-3614", "CVE-2012-3616", "CVE-2012-3617",
                "CVE-2012-3621", "CVE-2012-3622", "CVE-2012-3623", "CVE-2012-3624",
                "CVE-2012-3632", "CVE-2012-3643", "CVE-2012-3647", "CVE-2012-3648",
                "CVE-2012-3649", "CVE-2012-3651", "CVE-2012-3652", "CVE-2012-3654",
                "CVE-2012-3657", "CVE-2012-3658", "CVE-2012-3659", "CVE-2012-3660",
                "CVE-2012-3671", "CVE-2012-3672", "CVE-2012-3673", "CVE-2012-3675",
                "CVE-2012-3676", "CVE-2012-3677", "CVE-2012-3684", "CVE-2012-3685",
                "CVE-2012-3687", "CVE-2012-3688", "CVE-2012-3692", "CVE-2012-3699",
                "CVE-2012-3700", "CVE-2012-3701", "CVE-2012-3702", "CVE-2012-3703",
                "CVE-2012-3704", "CVE-2012-3705", "CVE-2012-3706", "CVE-2012-3707",
                "CVE-2012-3708", "CVE-2012-3709", "CVE-2012-3710", "CVE-2012-3711",
                "CVE-2012-3712");
  script_bugtraq_id(55624, 55625, 55626, 53679, 54203, 54386, 54680, 55534);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-10-01 12:01:34 +0530 (Mon, 01 Oct 2012)");
  script_name("Apple Safari Multiple Vulnerabilities - Oct 2012 (Mac OS X)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5502");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50577");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00005.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to disclose potentially
  sensitive information, bypass certain security restrictions and compromise
  a user's system.");
  script_tag(name:"affected", value:"Apple Safari versions prior to 6.0.1");
  script_tag(name:"insight", value:"For more details about the vulnerabilities refer the reference section.");
  script_tag(name:"solution", value:"Upgrade to Apple Safari version 6.0.1 or later.");
  script_tag(name:"summary", value:"This host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.apple.com/safari/download/");
  exit(0);
}


include("version_func.inc");

osName = "";
osVer = "";
safVer = "";

osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
  exit(0);
}

if("Mac OS X" >< osName)
{
  if(version_is_equal(version:osVer, test_version:"10.7.5")||
     version_is_equal(version:osVer, test_version:"10.8")||
     version_is_equal(version:osVer, test_version:"10.8.1"))
  {
    safVer = get_kb_item("AppleSafari/MacOSX/Version");
    if(!safVer){
      exit(0);
    }

    if(version_is_less(version:safVer, test_version:"6.0.1")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
