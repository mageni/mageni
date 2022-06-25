###############################################################################
# OpenVAS Vulnerability Test
#
# Double Pulsar Infection Detect
#
# Authors:
# Shakeel <bshakeel@secpod.com>
# Antu Sanadi <santu@secpod.com> on 2017-06-28Fixed the validation issues.
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
  script_oid("1.3.6.1.4.1.25623.1.0.810698");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0146", "CVE-2017-0147");
  script_bugtraq_id(96707, 96709);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-04-18 15:25:17 +0530 (Tue, 18 Apr 2017)");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("Double Pulsar Infection Detect");

  script_tag(name:"summary", value:"This host is vulnerable to 'Eternalblue'
  tool attack and is prone to remote code-execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send an SMB trans2 session setup request
  and check for presence of Multiplex ID '0x51' in the response.");

  script_tag(name:"insight", value:"An SMBv1 (Server Message Block 1.0) exploit
  that could trigger a RCE in older versions of Windows dubbed as 'ETERNALBLUE'
  has been discovered in latest dump of NSA Tools. One covert channel, 'double
  pulsar', is designed to particular for systems that are vulnerable to Eternalblue.
  The covert channel uses SMB features that have so far been not used, in
  particular, the 'Trans2' feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system. Failed attacks
  will cause denial of service conditions.");

  script_tag(name:"affected", value:"All Windows Platforms from Windows XP
  through Windows 2012");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://github.com/countercept/doublepulsar-detection-script");
  script_xref(name:"URL", value:"https://isc.sans.edu/forums/diary/Detecting+SMB+Covert+Channel+Double+Pulsar/22312");
  script_xref(name:"URL", value:"http://blog.binaryedge.io/2017/04/21/doublepulsar");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_smb_version_detect.nasl", "os_detection.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("smb_v1/supported", "Host/runs_windows");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-010");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");

name = kb_smb_name();
smbPort = kb_smb_transport();
if(!name || !smbPort){
  exit(0);
}

soc = open_sock_tcp( smbPort );
if( ! soc ) exit( 0 );

## SMB Negotiate Protocol Request
smb_neg_req = raw_string(0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42,
                         0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc0,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
                         0x00, 0x00, 0x40, 0x00, 0x00, 0x62, 0x00, 0x02,
                         0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
                         0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52,
                         0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02,
                         0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e,
                         0x30, 0x00, 0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f,
                         0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57,
                         0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70,
                         0x73, 0x20, 0x33, 0x2e, 0x31, 0x61, 0x00, 0x02,
                         0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30,
                         0x32, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41,
                         0x4e, 0x32, 0x2e, 0x31, 0x00, 0x02, 0x4e, 0x54,
                         0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32,
                         0x00);

## SMB Negotiate Protocol Response
send( socket:soc, data:smb_neg_req );
smb_neg_resp = smb_recv( socket:soc );
if(strlen(smb_neg_resp) < 9 || !ord(smb_neg_resp[9])==0)
{
  close( soc );
  exit( 0 );
}


## SMB Session Setup AndX Request,Anonymous User
smb_sess_req = raw_string(0x00, 0x00, 0x00, 0x88, 0xff, 0x53, 0x4d, 0x42,
                          0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xc0,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
                          0x00, 0x00, 0x40, 0x00, 0x0d, 0xff, 0x00, 0x88,
                          0x00, 0x04, 0x11, 0x0a, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x4b,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00,
                          0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00,
                          0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32, 0x00,
                          0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20, 0x00,
                          0x32, 0x00, 0x31, 0x00, 0x39, 0x00, 0x35, 0x00,
                          0x00, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6e, 0x00,
                          0x64, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x73, 0x00,
                          0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
                          0x30, 0x00, 0x20, 0x00, 0x35, 0x00, 0x2e, 0x00,
                          0x30, 0x00, 0x00, 0x00);

## Session Setup AndX Response
send( socket:soc, data:smb_sess_req );
smb_sess_resp = smb_recv( socket:soc );
if(strlen(smb_sess_resp) < 9 || !ord(smb_sess_resp[9])==0)
{
  close( soc );
  exit( 0 );
}

##Extract UID from Session Setup AndX Response
if(smb_sess_resp)
{
  uid_low   = ord(smb_sess_resp[32]);
  uid_high  = ord(smb_sess_resp[33]);
  uid   = uid_high * 256;
  uid  += uid_low;
}

## SMB Tree Connect AndX Request, Path: \\xxx.xxx.xxx.xxx\IPC$
smb_tree_resp = smb_tconx( soc:soc, name:name, uid:uid, share:"IPC$" );
if(strlen(smb_tree_resp) < 9 || !ord(smb_tree_resp[9])==0)
{
  close( soc );
  exit( 0 );
}

##Extract Tree ID from SMB Tree Connect Response
if(smb_tree_resp)
{
  tid_low = ord(smb_tree_resp[28] );
  tid_high = ord(smb_tree_resp[29] );
}

## SMB TRANS2 Request
smbtrans2_request = raw_string(0x00, 0x00, 0x00, 0x4e, 0xff, 0x53, 0x4d, 0x42,
                               0x32, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xc0,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00) + raw_string(tid_low, tid_high) +
                               raw_string(0xff, 0xfe) +  raw_string(uid_low, uid_high) +
                               raw_string(0x41, 0x00, 0x0f, 0x0c, 0x00, 0x00,
                               0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0xa6, 0xd9, 0xa4, 0x00, 0x00, 0x00, 0x0c,
                               0x00, 0x42, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x01,
                               0x00, 0x0e, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00 );

send( socket:soc, data: smbtrans2_request);

##Trans2 Response, SESSION_SETUP, Error: STATUS_NOT_IMPLEMENTED
smb_trans2_resp = smb_recv( socket:soc );
if(strlen(smb_trans2_resp) < 34)
{
  close( soc );
  exit( 0 );
}

##The intent of this request is to check if the system is already compromised.
##Infected or not, the system will respond with a "Not Implemented" message.
if(smb_trans2_resp && (ord(smb_trans2_resp[9])==2 && ord(smb_trans2_resp[10])==0
                   && ord(smb_trans2_resp[11])==0 && ord(smb_trans2_resp[12])==192))
{
  ##As part of the message, a "Multiplex ID" is returned.
  ##For normal systems it is 65 (0x41) and for infected systems it is 81 (0x51).
  if(ord(smb_trans2_resp[34]) == 81)
  {
    security_message(port:smbPort );
    close(soc);
    exit(0);
  }
}
close(soc);
