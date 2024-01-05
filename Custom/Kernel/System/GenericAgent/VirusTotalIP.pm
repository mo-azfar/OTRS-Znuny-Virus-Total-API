# --
# Copyright (C) 2022 mo-azfar, https://github.com/mo-azfar/
# --
# This software comes with ABSOLUTELY NO WARRANTY. For details, see
# the enclosed file COPYING for license information (GPL). If you
# did not receive this file, see https://www.gnu.org/licenses/gpl-3.0.txt.
# --
# Called out webservice from Generic Agent
# 1. Dynamic Field: IPAddress (text)

# 2. Generic Agent execute this.
# - Event: TicketDynamicFieldUpdate_IPAddress

# - Select Tickets
# -- Ticket# = *
# -- DynamicField_IPAddress = *

# - Execute Custom Module
# -- Module = Kernel::System::GenericAgent::VirusTotalIP

# -- Param 1 key	||	Param 1 value
# --- Webservice	||	VirusTotal

# -- Param 2 key	||	Param 2 value
# --- Invoker		||	GetIP

package Kernel::System::GenericAgent::VirusTotalIP;

use strict;
use warnings;

use Kernel::System::VariableCheck qw(:all);

our @ObjectDependencies = (
    'Kernel::System::Log',
    'Kernel::System::Ticket',
);

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    return $Self;
}

sub Run {
    my ( $Self, %Param ) = @_;

	local $Kernel::OM = Kernel::System::ObjectManager->new(
        'Kernel::System::Log' => {
            LogPrefix => 'VirusTotalIP', 
        },
    );
	
    # check needed param
    if ( !$Param{TicketID} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => 'Need TicketID for this operation',
        );
        return;
    }

    # check needed stuff
    for my $Needed (qw(Webservice Invoker)) {
        if ( !$Param{New}->{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );
            return;
        }
    }
	
	# execute defined webservice. all the sent data payload (Mapping for outgoing request data), endpoint, authentication handle by the defined webservice itself.
	# why use this method? the response json return invalid xml attributes when converting.
    # can be tackle by pre-filter regex, but to avoid future unknown invalid attribute, use this module. 
	# also allow more data mapping due complicated hash / array response data
	my $WebserviceObject = $Kernel::OM->Get('Kernel::System::GenericInterface::Webservice');
	my $RequesterObject = $Kernel::OM->Get('Kernel::GenericInterface::Requester');
		
	my $Webservice = $WebserviceObject->WebserviceGet(
	    Name => $Param{New}->{'Webservice'},
	);
	
    # webservice invoker backend must be Ticket::Generic
    my $Result = $RequesterObject->Run(
		WebserviceID => $Webservice->{ID},                      
		Invoker      => $Param{New}->{'Invoker'},       
		Asynchronous => 0,               # Optional, 1 or 0, defaults to 0
		Data         => {                # Data payload for the Invoker request
			TicketID => $Param{TicketID},
			#additional parameter to ws. Catch it by //Event/RefValue
			#RefValue => $SourceDynamicFieldValue,
		},
		    
	);

    if ( $Result->{Success} ne 1 )
	{
		return;
	}

    my $Data = $Result->{Data};

    my $NewValue1 = "<b>Last Analysis Stats</b><br/>";
	for my $NeededValue1 ( sort {lc $a cmp lc $b} keys %{ $Data->{data}->{attributes}->{last_analysis_stats} } )
	{
		$NewValue1 .= "- $NeededValue1: $Data->{data}->{attributes}->{last_analysis_stats}->{$NeededValue1}<br/>";
	}
	
    my $TableCSS = "
    <style>
    .DataTable {
        font-family: Arial, Helvetica, sans-serif;
        border-collapse: collapse;
        width: 80%;
    }

    .DataTable td, .DataTable th {
        border: 1px solid #ddd;
        padding: 8px;
    }

    .DataTable tr:nth-child(even){background-color: #f2f2f2;}

    .DataTable tr:hover {background-color: #ddd;}

    .DataTable th {
        padding-top: 12px;
        padding-bottom: 12px;
        text-align: left;
        background-color: #04AA6D;
        color: white;
    }
    </style>
    ";

    my $NewValue2 = "<b>Last Analysis Result</b><br/>";
    $NewValue2 .= "<table class='DataTable'>
    <thead>
    <tr>
    <th>Engine</th>
    <th>Category</th>
    <th>Method</th>
    <th>Result</th>
    </tr>
    </thead>
    <tbody>";
    
    for my $NeededValue2 ( sort {lc $a cmp lc $b} keys %{ $Data->{data}->{attributes}->{last_analysis_results} } )
	{
        #skip over undetected / empty result.
        next if $Data->{data}->{attributes}->{last_analysis_results}->{$NeededValue2}->{category} eq 'undetected';

        #delete not needed data
        delete($Data->{data}->{attributes}->{last_analysis_results}->{$NeededValue2}->{engine_name});
        
        $NewValue2 .= "<tr><td>$NeededValue2</td>";
        for my $NeededSubValue ( sort {lc $a cmp lc $b} keys %{ $Data->{data}->{attributes}->{last_analysis_results}->{$NeededValue2} } )
	    {
            $NewValue2 .= "<td>$Data->{data}->{attributes}->{last_analysis_results}->{$NeededValue2}->{$NeededSubValue}</td>";
        }
        $NewValue2 .= "<tr/>";
    }
    $NewValue2 .= "</tbody></table>";

    #create article with attachment
	my $ArticleObject = $Kernel::OM->Get('Kernel::System::Ticket::Article');
	#determine type of article to be created. Internal / Email / Phone
	my $ArticleBackendObject = $Kernel::OM->Get('Kernel::System::Ticket::Article')->BackendForChannel(ChannelName => 'Internal');

    #convert to json for attachment
	my $JSONString = $Kernel::OM->Get('Kernel::System::JSON')->Encode(
        Data     => $Data,
        SortKeys => 1,          # (optional) (0|1) default 0, to sort the keys of the json data
        Pretty => 1,            # (optional) (0|1) default 0, to pretty print
    );

    my $NewArticleID = $ArticleBackendObject->ArticleCreate(
        TicketID             => $Param{TicketID},                              
        SenderType           => 'system',                          #agent|system|customer
        IsVisibleForCustomer => 0,                                
        UserID               => 1,                              
        From           => "system",
        Subject        => "TotalVirus IP: $Data->{data}->{id}",               
        Body           => "$TableCSS This is response from TotalVirus for IP address $Data->{data}->{id}<br/><br/>For more value, please see the attachment.<br/><br/>$NewValue1<br/>$NewValue2",
		ContentType    => 'text/html; charset=UTF-8',    	
        HistoryType    => 'AddNote',                          
        HistoryComment => 'Add note from system',
		Attachment => [
            {
                Content     => $JSONString, #json data
                ContentType => 'application/json',
                Filename    => 'response.json',
            },
        ],
		NoAgentNotify    => 1,
    );

    return 1;
}

1;
