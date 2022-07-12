###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_css_bof_vuln.nasl 12631 2018-12-03 15:32:54Z cfischer $
#
# Apple Safari 'CSS' Buffer Overflow Vulnerability (Windows) - Dec09
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800155");
  script_version("$Revision: 12631 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:32:54 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4186");
  script_bugtraq_id(37039);
  script_name("Apple Safari 'CSS' Buffer Overflow Vulnerability (Windows) - Dec09");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54487");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/10102");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
code or cause the application to crash via long URI value in the CSS background
property.");
  script_tag(name:"affected", value:"Apple Safari version 4.0.3 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to improper bounds checking while processing
Cascading Style Sheets background images property.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Apple Safari Web Browser and is prone
to Buffer Overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

safariVer = get_kb_item("AppleSafari/Version");
if(safariVer != NULL)
{
  if(version_is_equal(version:safariVer, test_version:"4.31.9.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
