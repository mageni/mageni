###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X Multiple Vulnerabilities-01 July15
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805676");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2015-3720", "CVE-2015-3718", "CVE-2015-3716", "CVE-2015-3715",
                "CVE-2015-3714", "CVE-2015-3713", "CVE-2015-3712", "CVE-2015-3711",
                "CVE-2015-3709", "CVE-2015-3708", "CVE-2015-3707", "CVE-2015-3706",
                "CVE-2015-3705", "CVE-2015-3704", "CVE-2015-3702", "CVE-2015-3701",
                "CVE-2015-3700", "CVE-2015-3699", "CVE-2015-3698", "CVE-2015-3697",
                "CVE-2015-3696", "CVE-2015-3695", "CVE-2015-3693", "CVE-2015-3692",
                "CVE-2015-3691", "CVE-2015-3694", "CVE-2015-3689", "CVE-2015-3688",
                "CVE-2015-3687", "CVE-2015-3721", "CVE-2015-3719", "CVE-2015-3717",
                "CVE-2015-3710", "CVE-2015-3703", "CVE-2015-3690", "CVE-2015-3686",
                "CVE-2015-3685", "CVE-2015-3684", "CVE-2015-3683", "CVE-2015-3682",
                "CVE-2015-3681", "CVE-2015-3680", "CVE-2015-3679", "CVE-2015-3678",
                "CVE-2015-3677", "CVE-2015-3676", "CVE-2015-3675", "CVE-2015-3674",
                "CVE-2015-3673", "CVE-2015-3672", "CVE-2015-3671", "CVE-2015-0235",
                "CVE-2015-0273", "CVE-2015-1157", "CVE-2015-4000", "CVE-2014-8127",
                "CVE-2014-8128", "CVE-2014-8129", "CVE-2014-8130", "CVE-2015-1798",
                "CVE-2015-1799", "CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287",
                "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0293", "CVE-2015-3661",
                "CVE-2015-3662", "CVE-2015-3663", "CVE-2015-3666", "CVE-2015-3667",
                "CVE-2015-3668", "CVE-2013-1741", "CVE-2015-7036", "CVE-2014-8139",
                "CVE-2014-8140", "CVE-2014-8141");
  script_bugtraq_id(75493, 75495, 75491);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-07-10 12:16:49 +0530 (Fri, 10 Jul 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 July15");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists. For details refer
  reference section.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain sensitive information, execute arbitrary code, bypass intended launch
  restrictions and access restrictions, cause a denial of service, write to
  arbitrary files, execute arbitrary code with system privilege.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.10.x before
  10.10.4, 10.8.x through 10.8.5, 10.9.x through 10.9.5.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.10.4 or later or apply security update 2015-005 for 10.9.x and 10.8.x versions. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT204942");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/Jun/msg00002.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.([89]|10)");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.([89]|10)" || "Mac OS X" >!< osName){
  exit(0);
}

if((osVer == "10.9.5") || (osVer == "10.8.5"))
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }

  if(osVer == "10.9.5" && version_is_less(version:buildVer, test_version:"13F1096"))
  {
    fix = "Apply Security Update 2015-005";
    osVer = osVer + " Build " + buildVer;
  }

  else if(osVer == "10.8.5" && version_is_less(version:buildVer, test_version:"12F2542"))
  {
    fix = "Apply Security Update 2015-005";
    osVer = osVer + " Build " + buildVer;
  }
}

if(osVer =~ "^10\.9")
{
  if(version_is_less(version:osVer, test_version:"10.9.5")){
    fix = "Upgrade to latest OS release 10.9.5 and apply patch from vendor";
  }
}
else if(osVer =~ "^10\.8")
{
  if(version_is_less(version:osVer, test_version:"10.8.5")){
    fix = "Upgrade to latest OS release 10.8.5 and apply patch from vendor";
  }
}

else if(osVer =~ "^10\.10")
{
  if(version_is_less(version:osVer, test_version:"10.10.4")){
    fix = "10.10.4";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);