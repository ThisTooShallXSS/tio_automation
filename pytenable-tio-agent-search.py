""" --------------------------------------------------------------------------------------------------------------------
PyTenable - Tenable.io Search Agent Details by Agent Name

Before you can run this, you must generate an API Key that can be used for authentication. 
You can generate the API key using these steps: https://docs.tenable.com/tenableio/Content/Settings/GenerateAPIKey.htm

To install pyTenable:
    pip3 install pytenable 

Usage:
    $ python3 pytenable-tio-agent-search.py 
    $ python3 pytenable-tio-agent-search.py <AgentName>
    $ python3 pytenable-tio-agent-search.py Garys-Laptop

# ------------------------------------------------------------------------------------------------------------------ """

from tenable.io import TenableIO
tio = TenableIO('REPLACE_THIS_WITH_YOUR_ACCESS_KEY', 'REPLACE_THIS_WITH_YOUR_SECRET_KEY')

# Uncomment the 2 logging lines below to see ERROR or DEBUG logs in stdout while running the script.
# 
#import logging
#logging.basicConfig(level=logging.ERROR)

""" --------------------------------------------------------------------------------------------------------------------
Function: find_agent
Input: The hostname or full agent name as a str()
Output: The resulting agent.iterator from pytenable for any matching agents to the name filter.
Notes: This func assumes you've only matched a single agent for the name you provided. Needs to be
        expanded upon if you know there is likely to be multiple agents for a given name.
# ------------------------------------------------------------------------------------------------------------------ """

def find_agent(name):

    found_agent = 0

    for agent in tio.agents.list(('name', 'match', name)):
        found_agent = agent

    return agent

""" --------------------------------------------------------------------------------------------------------------------
Function: user_input_agent_name
Input: User input from input() in CLI, or receives "agent_name" as an argument of the script.
Output: Returns a str() of the desired agent name we're looking for.
Notes: This doesn't verify/regex to ensure proper formatting or naming conventions. Just makes sure its not null.
# ------------------------------------------------------------------------------------------------------------------ """

def user_input_agent_name():
    import sys
    
    agent_name = ""

    try:
        agent_name = sys.argv[1] # Try to use the arg passed in with the script.
    except:
        agent_name = input("Please provide your Agent name: ") # Allow user input if no args were passed in.

    if len(agent_name) == 0: # If the user hits enter/doesn't provide input, we will bail after returning an invalid name.
        print("This is an invalid agent name!")

    return agent_name

""" --------------------------------------------------------------------------------------------------------------------
Function: get_uuid_from_tenableid
Input: Receives the cleaned up tenable_id, which is not the same as a TIO asset UUID. Uses the agent name to 
        verify that we found the right agent based on the tenable_id.
Output: None, this is the function that outputs to CLI the information about the agent asset.
Notes: There could be more than one asset matched with the filter for the tenable_id. This is not accounted for.
# ------------------------------------------------------------------------------------------------------------------ """

def get_uuid_from_tenableid(tenable_id, agent_name):

    agents = tio.v3.explore.assets.search_host(
        filter={
              "and": [
                {
                  "property": "tenable_id",
                  "operator": "eq",
                  "value": [
                    tenable_id
                  ]
                },
                {
                  "property": "types",
                  "operator": "eq",
                  "value": "host"
                }
              ]
            },
        limit=2, sort=[('last_observed', 'asc')])

    return agents

""" --------------------------------------------------------------------------------------------------------------------
Function: search_for_agent_info
Input: None, this is our entry point. 
Output: This main function outputs the data in CLI when a matching agent is found.
Notes: 
# ------------------------------------------------------------------------------------------------------------------ """

def search_for_agent_info():
    from pprint import pprint

    tenable_id = 0 # Set this to zero, so we know if the search has failed.
    agent_name = user_input_agent_name() # Retrieve the agent_name from the CLI or argv[1]
    
    if len(agent_name) >= 3: # Adding some basic length check to ensure the name is valid before proceeding.

        agent_info = find_agent(agent_name)

        tenable_id = agent_info['uuid'] # The find_agent() func only returns a portion of the data we need about the agent. 
                                        # We store the "uuid" of the agent, which is really the tenable_id with hyphens.

        if tenable_id == 0: # By this point, if tenable_id is still zero then the find_agent() func failed.
            print("No matching agent found, or your spelling was off.")

        if len(tenable_id) == 36: # The agent UUID has hyphens, while the tenable_id does not.
            tenable_id = tenable_id.replace('-', '') # Remove the hyphens to convert the agent UUID to a tenable_id.

        print("Agent tenable_id: ", tenable_id) # Outputs the re-formatted agent tenable_id to CLI.

        agent_info = get_uuid_from_tenableid(tenable_id, agent_name) # This func returns a larger blob of asset details using the tenable_id.

        for agent in agent_info: # Ideally, this only loops once because you only matched a single agent.
            pprint(agent)        # This pretty-prints the json data about the matching agent. POC code to show how to get to the data.

if __name__ == '__main__':
    search_for_agent_info()

