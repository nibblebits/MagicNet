const MagicNetEventTypeInformation = [
    {
      id: "MAGICNET_EVENT_TYPE_NOT_USED",
      title: "Unused Event Type",
      description: "A NOT_USED event was passed. Usually, this type of event is not supposed to be fired."
    },
    {
      id: "MAGICNET_EVENT_TYPE_TEST",
      title: "Test Event",
      description: "Signifies a test event, usually sent when localhost connection first begins"
    },
    {
      id: "MAGICNET_EVENT_TYPE_NEW_BLOCK",
      title: "New Block Created",
      description: "A new block has been created"
    }
  ];

module.exports = {
    MagicNetEventTypeInformation,
};
