###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft IE CA SSL Certificate Security Bypass Vulnerability - Oct09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Antu sanadi <santu@secpod.com> on 2011-05-18
#  - This plugin is invalidated by secpod_ms09-056.nasl
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
  script_oid("1.3.6.1.4.1.25623.1.0.801109");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-10-06 07:21:15 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2510");
  script_bugtraq_id(36475);
  script_name("Microsoft IE CA SSL Certificate Security Bypass Vulnerability - Oct09");
  script_xref(name:"URL", value:"http://www.wired.com/threatlevel/2009/07/kaminsky/");
  script_xref(name:"URL", value:"http://www.networkworld.com/news/2009/073009-more-holes-found-in-webs.html");
  script_xref(name:"URL", value:"http://www.networkworld.com/news/2009/091709-microsoft-ie-security-hole.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform man-in-the-middle
  attacks or impersonate trusted servers, which will aid in further attack.");

  script_tag(name:"affected", value:"Microsoft IE version 6.x/7.x/8.x");

  script_tag(name:"insight", value:"Microsoft Internet Explorer fails to properly validate '\0' character in the
  domain name in a signed CA certificate, allowing attackers to substitute
  malicious SSL certificates for trusted ones.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is installed with Internet Explorer and is prone to
  Security Bypass vulnerability.

  This VT has been replaced by VT 'Microsoft Windows CryptoAPI X.509 Spoofing Vulnerabilities (974571)' (OID: 1.3.6.1.4.1.25623.1.0.900876).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # This plugin is invalidated by secpod_ms09-056.nasl