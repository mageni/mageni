###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bpftp_client_bof_vuln.nasl 14330 2019-03-19 13:59:11Z asteins $
#
# BulletProof FTP Client '.bps' File Buffer Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800330");
  script_version("$Revision: 14330 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:59:11 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-01-06 15:38:06 +0100 (Tue, 06 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5753", "CVE-2008-5754");
  script_bugtraq_id(33007, 33024);
  script_name("BulletProof FTP Client '.bps' File Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33322");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7571");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7589");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_bpftp_detect.nasl");
  script_mandatory_keys("BulletProof/Client/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary codes in
  the context of the application and can cause Denial of Service to the
  application.");
  script_tag(name:"affected", value:"BulletProof FTP Client version 2.63.0.56 or prior on Windows");
  script_tag(name:"insight", value:"The flaw is due to improper boundary checks in .bps file with a long
  second line and bookmark file entry with a long host name.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host has BulletProof FTP Client installed and is prone to
  Stack-Based Buffer Overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.bpftp.com/");
  exit(0);
}


include("version_func.inc");

ver = get_kb_item("BulletProof/Client/Ver");
if(!ver){
  exit(0);
}

if(version_is_less_equal(version:ver, test_version:"2.63.0.56")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
