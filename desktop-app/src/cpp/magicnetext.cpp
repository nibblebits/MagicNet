
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

v8::Local<v8::Object> LibMagicNetBlockToJs(struct block *block)
{
  v8::Local<v8::Object> block_obj = Nan::New<v8::Object>();

  // Set the hash
  Nan::Set(block_obj, Nan::New("hash").ToLocalChecked(), Nan::New(std::string(block->hash, strnlen(block->hash, sizeof(block->hash)))).ToLocalChecked());
  Nan::Set(block_obj, Nan::New("prev_hash").ToLocalChecked(), Nan::New(std::string(block->prev_hash, strnlen(block->prev_hash, sizeof(block->prev_hash)))).ToLocalChecked());
  Nan::Set(block_obj, Nan::New("time").ToLocalChecked(), Nan::New<v8::Number>(block->time));
  Nan::Set(block_obj, Nan::New("key").ToLocalChecked(), Nan::New(std::string(block->key.key, strnlen(block->key.key, sizeof(block->key.key)))).ToLocalChecked());

  return block_obj;
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

  // If the event is null, then there's no event.
  if (!event)
  {
    info.GetReturnValue().Set(Nan::Null());
    return;
  }

  int eventIndex = LibMagicNetPushPointer(event);

  // Create a JS object to hold the event data
  v8::Local<v8::Object> jsEvent = Nan::New<v8::Object>();
  Nan::Set(jsEvent, Nan::New("ptr_id").ToLocalChecked(), Nan::New(eventIndex));
  Nan::Set(jsEvent, Nan::New("id").ToLocalChecked(), Nan::New(event->id));
  Nan::Set(jsEvent, Nan::New("type").ToLocalChecked(), Nan::New(event->type));

  v8::Local<v8::Object> js_event_data = Nan::New<v8::Object>();
  switch (event->type)
  {
  case MAGICNET_EVENT_TYPE_NEW_BLOCK:
    v8::Local<v8::Object> js_new_block_event = Nan::New<v8::Object>();
    v8::Local<v8::Object> js_block_obj = LibMagicNetBlockToJs(event->data.new_block_event.block);
    Nan::Set(js_new_block_event, Nan::New("block").ToLocalChecked(),js_block_obj);
    Nan::Set(js_event_data, Nan::New("new_block_event").ToLocalChecked(), js_new_block_event);
    break;
  }

  Nan::Set(jsEvent, Nan::New("data").ToLocalChecked(), js_event_data);

  // Return the JS object
  info.GetReturnValue().Set(jsEvent);
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
}

NODE_MODULE(magicnet, Init)
