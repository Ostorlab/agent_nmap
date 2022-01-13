"""Sample agent implementation"""
from ostorlab.agent import agent
from ostorlab.agent import message as m

class HellWorldAgent(agent.Agent):
    """Hello world agent."""

    def process(self, message: m.Message) -> None:
        """TODO (author): add your description here.

        Args:
            message:

        Returns:

        """
        # TODO (author): implement agent logic here.
        del message
        self.emit('v3.healthcheck.ping', {'body': 'Hello World!'})
