###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_info_disc_n_spoof_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# MS IE Information Disclosure and Web Site Spoofing Vulnerabilities
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803305");
  script_version("$Revision: 11401 $");
  script_bugtraq_id(57640, 57641);
  script_cve_id("CVE-2013-1450", "CVE-2013-1451");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-02-04 11:45:52 +0530 (Mon, 04 Feb 2013)");
  script_name("MS IE Information Disclosure and Web Site Spoofing Vulnerabilities");
  script_xref(name:"URL", value:"http://pastebin.com/raw.php?i=rz9BcBey");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2013-1450");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2013-1451");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2013-1450");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2013-1451");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to disclose the
sensitive information and view the contents of spoofed site or carry out
phishing attacks.");
  script_tag(name:"affected", value:"Microsoft Internet Explorer versions 8 and 9");
  script_tag(name:"insight", value:"The proxy settings configuration has same proxy address and value for HTTP
  and HTTPS,

  - TCP session to proxy sever will not properly be reused. This allows remote
  attackers to steal cookie information via crafted HTML document.

  - SSl lock consistency with address bar is not ensured. This allows remote
  attackers to spoof web sites via a crafted HTML document.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Microsoft Internet Explorer and is
prone to information disclosure and web site spoofing vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");

if(ieVer && ieVer =~ "^(8|9)"){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
