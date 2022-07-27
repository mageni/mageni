###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_taskmgr_info_disc_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# MS Windows taskmgr.exe Information Disclosure Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.org
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
  script_oid("1.3.6.1.4.1.25623.1.0.900302");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-02-03 15:40:18 +0100 (Tue, 03 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2009-0320");
  script_bugtraq_id(33440);
  script_name("MS Windows taskmgr.exe Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://www.unifiedds.com/?p=44");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/500393/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");

  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker retrieve password related
  information and can cause brute force or benchmarking attacks.");
  script_tag(name:"affected", value:"Microsoft Windows XP SP3 and prior.
  Microsoft Windows Server 2003 SP2 and prior.");
  script_tag(name:"insight", value:"The I/O activity measurement of all processes allow to obtain sensitive
  information by reading the I/O other bytes column in taskmgr.exe to
  estimate the number of characters that a different user entered at a
  password prompt through 'runas.exe'.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Windows Operating System and is prone to
  information disclosure vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/en/us/default.aspx");
  exit(0);
}


include("secpod_reg.inc");

exit(0); ## plugin may results to FP

if(hotfix_check_sp(xp:4, win2003:3) > 0){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
