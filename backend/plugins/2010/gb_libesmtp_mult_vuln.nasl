###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libesmtp_mult_vuln.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# libESMTP multiple vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800497");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_cve_id("CVE-2010-1194", "CVE-2010-1192");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("libESMTP multiple vulnerabilities");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=571817");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/03/09/3");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/03/03/6");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_libesmtp_detect.nasl");
  script_mandatory_keys("libESMTP/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue to conduct man-in-the-middle attacks to
  spoof arbitrary SSL servers and to spoof trusted certificates.");
  script_tag(name:"affected", value:"libESMTP version 1.0.4 and prior.");
  script_tag(name:"solution", value:"Apply patch

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****");
  script_tag(name:"summary", value:"This host has libESMTP installed and is prone to multiple
  vulnerabilities.

  Vulnerabilities Insight:
  Multiple flaws are due to:

  - An error in 'match_component()' function in 'smtp-tls.c' when processing
    substrings. It treats two strings as equal if one is a substring of the
    other, which allows attackers to spoof trusted certificates via a crafted
    subjectAltName.

  - An error in handling of 'X.509 certificate'. It does not properly
    handle a '&qt?&qt' character in a domain name in the 'subject&qts Common Name'
    field of an X.509 certificate, which allows man-in-the-middle attackers to
    spoof arbitrary SSL servers via a crafted certificate.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=399131&action=edit");
  exit(0);
}


include("version_func.inc");

libesmtpVer = get_kb_item("libESMTP/Ver");
if(libesmtpVer != NULL)
{
  if(version_is_less_equal(version:libesmtpVer, test_version:"1.0.4")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
