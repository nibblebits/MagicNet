
/**
 * This is the extension that will be used in electron to bind a bridge between javascript
 * and our Magicnet decentralized network framework
 */

#include <nan.h>
#include <map>
#include <string>

extern "C"
{
#include "magicnet/magicnet.h"
}

std::map<int, void *> pointer_map;
int pointer_id = 1000;

int LibMagicNetPushPointer(void *ptr)
{
  int ptr_id = -1;
  pointer_map[pointer_id] = ptr;
  ptr_id = pointer_id;
  pointer_id++;
  return ptr_id;
}

void *LibMagicNetGetPointer(int index)
{
  if (pointer_map.find(index) == pointer_map.end())
  {
    Nan::ThrowError("The index is not a pointer");
  }
  return pointer_map[index];
}

void LibMagicNetCreateProgram(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
  // validate and convert arguments from JavaScript...

  if (info.Length() < 1)
  {
    Nan::ThrowTypeError("Arity mismatch");
    return;
  }

  // Validate the type of the first argument.
  if (!info[0]->IsString())
  {
    Nan::ThrowTypeError("Argument must be a string");
    return;
  }

  v8::String::Utf8Value program_name(Nan::GetCurrentContext()->GetIsolate(), info[0]);
  struct magicnet_program *program = magicnet_program(*program_name);
  if (!program)
  {
    Nan::ThrowTypeError("Failed to create a new program instance is the magicnet server running");
  }
  int index = LibMagicNetPushPointer(program);

  // return the index to JavaScript...
  v8::Local<v8::Number> res_num = Nan::New(index);
  info.GetReturnValue().Set(res_num);
}

void LibMagicNet_Init(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
  if (info.Length() < 1)
  {
    Nan::ThrowTypeError("Arity mismatch");
    return;
  }

  // Validate the type of the first argument.
  if (!info[0]->IsNumber())
  {
    Nan::ThrowTypeError("Argument must be a number");
    return;
  }

  // Convert the first argument to a number
  int flags = info[0]->NumberValue(Nan::GetCurrentContext()).FromJust();

  // Initialize the magicnet library
  int res = magicnet_init(flags);
  v8::Local<v8::Number> res_num = Nan::New(res);
  info.GetReturnValue().Set(res_num);
}

void LibMagicNetEventType(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
  // Validate and convert arguments from JavaScript...
  if (info.Length() < 1)
  {
    Nan::ThrowTypeError("Arity mismatch");
    return;
  }

  // Validate the type of the first argument.
  if (!info[0]->IsNumber())
  {
    Nan::ThrowTypeError("Argument must be a number");
    return;
  }

  int index = info[0]->NumberValue(Nan::GetCurrentContext()).FromJust();

  // Get the program pointer from the map
  struct magicnet_event *event = static_cast<struct magicnet_event *>(LibMagicNetGetPointer(index));
  if (!event)
  {
      Nan::ThrowTypeError("The event has expired and no longer accessible");
      return;
  }

  info.GetReturnValue().Set(Nan::New(event->type));
}

void LibMagicNetNextEvent(const Nan::FunctionCallbackInfo<v8::Value> &info)
{
  // Validate and convert arguments from JavaScript...
  if (info.Length() < 1)
  {
    Nan::ThrowTypeError("Arity mismatch");
    return;
  }

  // Validate the type of the first argument.
  if (!info[0]->IsNumber())
  {
    Nan::ThrowTypeError("Argument must be a number");
    return;
  }

  // Convert the first argument to a number (the index of the program)
  int index = info[0]->NumberValue(Nan::GetCurrentContext()).FromJust();

  // Get the program pointer from the map
  struct magicnet_program *program = static_cast<struct magicnet_program *>(LibMagicNetGetPointer(index));

  // Get the next event
  struct magicnet_event *event = magicnet_next_event(program);

  // If the event is null, then theirs no event.
  if (!event)
  {
    info.GetReturnValue().Set(Nan::New(0));
    return;
  }

  // Store the event pointer and get its index
  int eventIndex = LibMagicNetPushPointer(event);

  // return the index to JavaScript...
  v8::Local<v8::Number> res_num = Nan::New(eventIndex);
  info.GetReturnValue().Set(res_num);
}

void Init(v8::Local<v8::Object> exports)
{
  v8::Local<v8::FunctionTemplate> magicnetInitFunction = Nan::New<v8::FunctionTemplate>(LibMagicNet_Init);
  Nan::Set(exports, Nan::New("magicnet_init").ToLocalChecked(),
           Nan::GetFunction(magicnetInitFunction).ToLocalChecked());

  v8::Local<v8::FunctionTemplate> magicnetProgramFunction = Nan::New<v8::FunctionTemplate>(LibMagicNetCreateProgram);
  Nan::Set(exports, Nan::New("magicnet_program").ToLocalChecked(),
           Nan::GetFunction(magicnetProgramFunction).ToLocalChecked());

  v8::Local<v8::FunctionTemplate> magicNetNextEventFunction = Nan::New<v8::FunctionTemplate>(LibMagicNetNextEvent);
  Nan::Set(exports, Nan::New("magicnet_next_event").ToLocalChecked(),
           Nan::GetFunction(magicNetNextEventFunction).ToLocalChecked());

  v8::Local<v8::FunctionTemplate> magicNetEventTypeFunction = Nan::New<v8::FunctionTemplate>(LibMagicNetEventType);
  Nan::Set(exports, Nan::New("magicnet_event_type").ToLocalChecked(),
        Nan::GetFunction(magicNetEventTypeFunction).ToLocalChecked());
      
}

NODE_MODULE(magicnet, Init)
