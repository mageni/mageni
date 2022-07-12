###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_webkit_mult_vuln_mar12_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Apple Safari Webkit Multiple Vulnerabilities - March12 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802814");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-0584", "CVE-2012-0585", "CVE-2011-3881", "CVE-2012-0586",
                "CVE-2012-0587", "CVE-2012-0588", "CVE-2012-0589", "CVE-2011-3887",
                "CVE-2012-0590", "CVE-2011-2825", "CVE-2011-2833", "CVE-2011-2846",
                "CVE-2011-2847", "CVE-2011-2854", "CVE-2011-2855", "CVE-2011-2857",
                "CVE-2011-2860", "CVE-2011-2866", "CVE-2011-2867", "CVE-2011-2868",
                "CVE-2011-2869", "CVE-2011-2870", "CVE-2011-2871", "CVE-2011-2872",
                "CVE-2011-2873", "CVE-2011-2877", "CVE-2011-3885", "CVE-2011-3888",
                "CVE-2011-3897", "CVE-2011-3908", "CVE-2011-3909", "CVE-2011-3928",
                "CVE-2012-0591", "CVE-2012-0592", "CVE-2012-0593", "CVE-2012-0594",
                "CVE-2012-0595", "CVE-2012-0596", "CVE-2012-0597", "CVE-2012-0598",
                "CVE-2012-0599", "CVE-2012-0600", "CVE-2012-0601", "CVE-2012-0602",
                "CVE-2012-0603", "CVE-2012-0604", "CVE-2012-0605", "CVE-2012-0606",
                "CVE-2012-0607", "CVE-2012-0608", "CVE-2012-0609", "CVE-2012-0610",
                "CVE-2012-0611", "CVE-2012-0612", "CVE-2012-0613", "CVE-2012-0614",
                "CVE-2012-0615", "CVE-2012-0616", "CVE-2012-0617", "CVE-2012-0618",
                "CVE-2012-0619", "CVE-2012-0620", "CVE-2012-0621", "CVE-2012-0622",
                "CVE-2012-0623", "CVE-2012-0624", "CVE-2012-0625", "CVE-2012-0626",
                "CVE-2012-0627", "CVE-2012-0628", "CVE-2012-0629", "CVE-2012-0630",
                "CVE-2012-0631", "CVE-2012-0632", "CVE-2012-0633", "CVE-2012-0635",
                "CVE-2012-0636", "CVE-2012-0637", "CVE-2012-0638", "CVE-2012-0639",
                "CVE-2012-0648", "CVE-2012-0640", "CVE-2012-0647");
  script_bugtraq_id(52419, 52364, 50360, 52367, 52367, 52367, 52367, 50360,
                    52367, 49279, 52365, 49658, 49658, 49658, 49658, 49658,
                    49658, 52363, 52365, 52365, 52365, 52365, 52365, 52365,
                    52365, 49938, 50360, 50360, 50642, 51041, 51041, 51641,
                    52365, 52365, 52365, 52365, 52365, 52365, 52365, 52365,
                    52365, 52365, 52365, 52365, 52365, 52365, 52365, 52365,
                    52365, 52365, 52365, 52365, 52365, 52365, 52365, 52365,
                    52365, 52365, 52365, 52365, 52365, 52365, 52365, 52365,
                    52365, 52365, 52365, 52365, 52365, 52365, 52365, 52365,
                    52365, 52365, 52365, 52365, 52363, 52363, 52363, 52363,
                    52363, 52423, 52421);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-13 18:17:52 +0530 (Tue, 13 Mar 2012)");
  script_name("Apple Safari Webkit Multiple Vulnerabilities - March12 (Windows)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5190");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48377");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Mar/msg00003.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to disclose potentially
  sensitive information, conduct cross-site scripting and spoofing attacks,
  and compromise a user's system.");
  script_tag(name:"affected", value:"Apple Safari versions prior to 5.1.4 on Windows");
  script_tag(name:"insight", value:"For more information on the vulnerabilities refer the reference section.");
  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.1.4 or later.");
  script_tag(name:"summary", value:"The host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.apple.com/support/downloads/");
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

if(version_is_less(version:safVer, test_version:"5.34.54.16")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
