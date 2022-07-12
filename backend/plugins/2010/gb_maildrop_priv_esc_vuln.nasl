##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_maildrop_priv_esc_vuln.nasl 12694 2018-12-06 15:28:57Z cfischer $
#
# Maildrop Privilege Escalation Vulnerability.
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
################################i###############################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800292");
  script_version("$Revision: 12694 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-06 16:28:57 +0100 (Thu, 06 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0301");
  script_name("Maildrop Privilege Escalation Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38367");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55980");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jan/1023515.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_maildrop_detect.nasl");
  script_mandatory_keys("Maildrop/Linux/Ver");

  script_tag(name:"insight", value:"The flaw is due to the error in the 'maildrop/main.C', when run by root
  with the '-d' option, uses the gid of root for execution of the mailfilter file
  in a user's home directory.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Maildrop version 2.4.0");
  script_tag(name:"summary", value:"This host is installed Maildrop and is prone to Privilege Escalation
  vulnerability");
  script_tag(name:"impact", value:"Successful exploitation will allow local users to gain elevated privileges.");
  script_tag(name:"affected", value:"Maildrop version 2.3.0 and prior.");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/courier/files/");
  exit(0);
}


include("version_func.inc");

mailVer = get_kb_item("Maildrop/Linux/Ver");
if(!mailVer){
  exit(0);
}

if(version_is_less_equal(version:mailVer, test_version:"2.3.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
