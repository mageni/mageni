###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smbv1_unspecified_rce_vuln.nasl 12467 2018-11-21 14:04:59Z cfischer $
#
# SMBv1 enabled
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810554");
  script_version("$Revision: 12467 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 15:04:59 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-02-15 13:56:01 +0530 (Wed, 15 Feb 2017)");
  script_name("SMBv1 enabled.");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_dependencies("gb_smbv1_server_detect.nasl", "gb_smbv1_client_detect.nasl");
  script_mandatory_keys("smb_v1/enabled");

  script_xref(name:"URL", value:"https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2696547");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/204279");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS17-010");

  script_tag(name:"summary", value:"The host has enabled SMBv1 for the SMB Client or Server and is prone to
  an unspecified remote code execution vulnerability.

  This NVT has been replaced by NVT 'Microsoft Windows SMB Server Multiple Vulnerabilities (4013389)'
  (OID: 1.3.6.1.4.1.25623.1.0.810676).");

  script_tag(name:"vuldetect", value:"Check if SMBv1 is enabled for the SMB Client or Server on the host
  with the help of detect nvt.");

  script_tag(name:"insight", value:"The flaw exists due to enabling of SMB
  Protocol Version 1 for the SMB Client or Server on the host.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Windows host with SMBv1 enabled for the SMB Client or Server.");

  script_tag(name:"solution", value:"Disable SMBv1 for the SMB Client and Server. Additionally block all
  versions of SMB at the network boundary by blocking TCP port 445 with related
  protocols on UDP ports 137-138 and TCP port 139, for all boundary devices.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

if( get_kb_item( "smb_v1/enabled" ) ) {
  report = 'The Windows host is prone to an unspecified remote code execution vulnerability in the SMBv1 protocol:\n';
  if( get_kb_item( "smb_v1_server/enabled" ) ) report += '\n- SMBv1 is enabled for the SMB Server';
  if( get_kb_item( "smb_v1_client/enabled" ) ) report += '\n- SMBv1 is enabled for the SMB Client';
  log_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );